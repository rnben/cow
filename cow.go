package main

import (
	"fmt"
	"github.com/pkg/sftp"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	Version     = "unknown"
	CommitID    = "unknown"
	sshSessions = sync.Map{}
)

type Config struct {
	Remote    []Remote  `yaml:"remote"`
	Operation Operation `yaml:"operator"`
}

type Remote struct {
	Host     string `yaml:"host"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Arch     string `yaml:"arch,omitempty"`
}

type EnvVar struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

type Operation struct {
	Disable    []string `yaml:"disable,omitempty"`
	Enable     []string `yaml:"enable,omitempty"`
	EnableAll  bool     `yaml:"enable-all,omitempty"`
	DisableAll bool     `yaml:"disable-all,omitempty"`
	Action     []Action `yaml:"action"`
}

type Action struct {
	Type       string   `yaml:"action"`
	Env        []EnvVar `yaml:"env,omitempty"`
	MainPath   string   `yaml:"mainPath,omitempty"`
	Output     string   `yaml:"output,omitempty"`
	BuildVars  []EnvVar `yaml:"buildVars,omitempty"`
	LocalFile  string   `yaml:"localFile,omitempty"`
	RemotePath string   `yaml:"remotePath,omitempty"`
	Target     []string `yaml:"target,omitempty"`
	Command    []string `yaml:"command,omitempty"`
}

var config Config

func main() {
	var rootCmd = &cobra.Command{
		Use:   "tool",
		Short: "A CLI tool to manage deployment tasks",
	}

	rootCmd.AddCommand(deployCmd, generateCmd, versionCmd)
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

var deployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "Execute defined operators such as build, upload, or command",
	Run: func(cmd *cobra.Command, args []string) {
		loadConfig()

		for _, remote := range config.Remote {
			getSSHClient(remote.Host, remote.Username, remote.Password)
		}

		jump := map[string]bool{}
		for _, d := range config.Operation.Disable {
			jump[d] = true
		}

		for _, op := range config.Operation.Action {
			if jump[op.Type] {
				continue
			}

			switch op.Type {
			case "build":
				arch := ""
				buildArgs := []string{"build"}

				for _, env := range op.Env {
					if env.Name == "GOARCH" {
						arch = env.Value
						break
					}
				}

				ldFlags := ""
				for _, buildVar := range op.BuildVars {
					value := resolveDynamicValue(buildVar.Value)
					ldFlags += fmt.Sprintf("-X '%s=%s' ", buildVar.Name, value)
				}

				mainPath := op.MainPath
				if mainPath == "" {
					mainPath = "."
				}

				outputFile := op.Output
				if outputFile != "" {
					outputFile = resolveGoArchDynamicValue(outputFile, arch)
					buildArgs = append(buildArgs, "-o", outputFile)
				}

				if ldFlags != "" {
					buildArgs = append(buildArgs, "-ldflags", ldFlags)
				}

				buildArgs = append(buildArgs, mainPath)

				log.Println("[build]", "go", strings.Join(buildArgs, " "))
				cmd := exec.Command("go", buildArgs...)
				cmd.Env = os.Environ()
				for _, env := range op.Env {
					cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", env.Name, env.Value))
				}
				if output, err := cmd.CombinedOutput(); err != nil {
					log.Fatalf("[build] build failed: %s %s\n", output, err)
				}
			case "upload":
				for _, target := range op.Target {
					for _, remote := range config.Remote {
						if remote.Host == target {
							localFile := resolveGoArchDynamicValue(op.LocalFile, remote.Arch)
							err := uploadFileSFTP(localFile, remote.Host, remote.Username, remote.Password, op.RemotePath)
							if err != nil {
								log.Printf("[upload] failed to upload file to %s: %v\n", target, err)
							}
						}
					}
				}
			case "command":
				for _, target := range op.Target {
					for _, cmd := range op.Command {
						for _, remote := range config.Remote {
							if remote.Host == target {
								fmt.Printf("Executing '%s' on %s\n", cmd, target)
								err := executeRemoteCommand(remote.Host, remote.Username, remote.Password, cmd)
								if err != nil {
									log.Printf("Failed to execute command '%s' on %s: %v\n", cmd, target, err)
								}
							}
						}
					}
				}
			}
		}
	},
}

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a default configuration file",
	Run: func(cmd *cobra.Command, args []string) {
		defaultConfig := Config{
			Remote: []Remote{
				{Host: "127.0.0.1", Username: "root", Password: "123456"},
				{Host: "192.168.1.2", Username: "root", Password: "123456"},
			},
			Operation: Operation{
				Disable: []string{"build"},
				Action: []Action{
					{Type: "build", Env: []EnvVar{{Name: "GOOS", Value: "linux"}, {Name: "GOARCH", Value: "amd64"}}, BuildVars: []EnvVar{{Name: "main.Version", Value: "{BRANCH_NAME}"}, {Name: "main.CommitID", Value: "{COMMIT_ID}"}}, MainPath: ".", Output: "./bin/{GOARCH}/cow_main"},
					{Type: "upload", LocalFile: "./bin/{GOARCH}/cow_main", RemotePath: "/tmp", Target: []string{"127.0.0.1", "192.168.1.2"}},
					{Type: "command", Target: []string{"127.0.0.1", "192.168.1.2"}, Command: []string{"date"}},
				}}}
		data, err := yaml.Marshal(&defaultConfig)
		if err != nil {
			log.Fatalf("[generate] failed to marshal default config: %s\n", err)
		}

		if err := ioutil.WriteFile("cow.deploy.yaml", data, 0644); err != nil {
			log.Fatalf("[generate] failed to write default config file: %s\n", err)
		}

		fmt.Println("[generate] default configuration file generated as 'cow.deploy.yaml'")
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display the version of the tool",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Version: %s.%s\n", Version, CommitID)
	},
}

func loadConfig() {
	file, err := ioutil.ReadFile("cow.deploy.yaml")
	if err != nil {
		log.Fatalf("Failed to read config file: %s\n", err)
	}

	if err := yaml.Unmarshal(file, &config); err != nil {
		log.Fatalf("Failed to parse config file: %s\n", err)
	}
}

func resolveDynamicValue(value string) string {
	if strings.Contains(value, "{BRANCH_NAME}") {
		branchName := getGitBranchName()
		value = strings.ReplaceAll(value, "{BRANCH_NAME}", branchName)
	}
	if strings.Contains(value, "{COMMIT_ID}") {
		commitID := getGitCommitID()
		value = strings.ReplaceAll(value, "{COMMIT_ID}", commitID)
	}
	return value
}

func resolveGoArchDynamicValue(value string, newValue string) string {
	if newValue == "" {
		newValue = os.Getenv("GOARCH")
	}
	value = strings.ReplaceAll(value, "{GOARCH}", newValue)
	return value
}
func getGitBranchName() string {
	cmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		log.Fatalf("Failed to get git branch name: %s\n", err)
	}
	return strings.TrimSpace(string(output))
}

func getGitCommitID() string {
	cmd := exec.Command("git", "rev-parse", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		log.Fatalf("Failed to get git commit ID: %s\n", err)
	}
	return strings.TrimSpace(string(output))
}

func uploadFileSFTP(localFile, remoteHost, username, password, remotePath string) error {
	log.Printf("[upload] uploading file %s to %s\n", localFile, remoteHost)

	conn, err := getSSHClient(remoteHost, username, password)
	if err != nil {
		return fmt.Errorf("failed to get SSH client: %w", err)
	}

	arch, err := GetServerGOARCH(conn)
	if err != nil {
		return fmt.Errorf("failed to get server GOARCH: %w", err)
	}
	if !strings.Contains(localFile, arch) {
		return fmt.Errorf("local file %s support %s[%s]", localFile, remoteHost, arch)
	}

	// 创建 SFTP 客户端
	client, err := sftp.NewClient(conn)
	if err != nil {
		return fmt.Errorf("failed to create SFTP client: %w", err)
	}
	defer client.Close()

	// 检查远程路径是否存在同名文件
	localFileName := filepath.Base(localFile)
	remoteFile := fmt.Sprintf("%s/%s", remotePath, localFileName)
	_, err = client.Stat(remoteFile)
	if err == nil {
		// 同名文件存在，创建备份
		timestamp := time.Now().Format("20060102150405")
		backupPath := fmt.Sprintf("%s_%s_bak", remoteFile, timestamp)
		if err := client.Rename(remoteFile, backupPath); err != nil {
			return fmt.Errorf("failed to backup existing file: %w", err)
		}
		log.Printf("[upload] backup created: %s\n", backupPath)
	}

	// 打开本地文件
	srcFile, err := os.Open(localFile)
	if err != nil {
		return fmt.Errorf("failed to open local file: %w", err)
	}
	defer srcFile.Close()

	// 确保远程目录存在
	err = client.MkdirAll(remotePath)
	if err != nil {
		return fmt.Errorf("[upload] failed to create remote directory: %w", err)
	}

	// 上传文件
	dstFile, err := client.Create(remoteFile)
	if err != nil {
		return fmt.Errorf("[upload] failed to create remote file: %w", err)
	}
	defer dstFile.Close()

	_, err = dstFile.ReadFrom(srcFile)
	if err != nil {
		return fmt.Errorf("[upload] failed to upload file content: %w", err)
	}

	// 修改远程文件权限为 755
	err = client.Chmod(remoteFile, 0755)
	if err != nil {
		return fmt.Errorf("[upload] failed to change file permissions: %w", err)
	}

	log.Printf("[upload] successfully uploaded %s to %s:%s\n", localFile, remoteHost, remoteFile)

	return nil
}

// executeRemoteCommand executes a command on a remote server via SSH
func executeRemoteCommand(host, username, password, command string) error {
	conn, err := getSSHClient(host, username, password)
	if err != nil {
		return fmt.Errorf("failed to get SSH client: %w", err)
	}

	// Open a session
	session, err := conn.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	// Run the command and capture the output
	output, err := session.CombinedOutput(command)
	fmt.Printf("Output from %s: %s\n", host, string(output))
	if err != nil {
		fmt.Printf("Error executing command on %s: %v\n", host, err)
	}

	return nil
}

func getSSHClient(host, username, password string) (*ssh.Client, error) {
	key := fmt.Sprintf("%s@%s", username, host)
	if client, ok := sshSessions.Load(key); ok {
		return client.(*ssh.Client), nil
	}

	c := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", host+":22", c)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to remote host: %w", err)
	}

	arch, err := GetServerGOARCH(client)
	if err != nil {
		return nil, fmt.Errorf("failed to get server GOARCH: %w", err)
	}

	for i := range config.Remote {
		if config.Remote[i].Host == host {
			config.Remote[i].Arch = arch
		}
	}

	sshSessions.Store(key, client)
	return client, nil
}

// GetServerGOARCH 通过 SSH 获取服务器的架构，并返回对应的 GOARCH 值
func GetServerGOARCH(client *ssh.Client) (string, error) {
	// 执行 uname -m 命令，获取服务器的架构信息
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	// 获取命令输出
	output, err := session.CombinedOutput("uname -m")
	if err != nil {
		return "", err
	}

	// 将输出的结果去掉多余的空格并转换为小写
	arch := strings.TrimSpace(string(output))

	// 映射服务器架构到 GOARCH
	var goarch string
	switch arch {
	case "x86_64":
		goarch = "amd64"
	case "aarch64":
		goarch = "arm64"
	case "arm64":
		goarch = "arm64"
	case "armv7l":
		goarch = "arm"
	default:
		return "", fmt.Errorf("unknown architecture: %s", arch)
	}

	return goarch, nil
}
