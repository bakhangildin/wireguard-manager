package main

import (
	"bufio"
	"bytes"
	"fmt"
	"html/template"
	"net"
	"os"
	"os/exec"
	"strings"
)

type Client struct {
	Name         string `json:"name"`
	PublicKey    string
	PrivateKey   string
	AllowedIPs   string `json:"ip"`
	Transfer     string `json:"transfer"`
	TunnelConfig string `json:"tunnel_config"`
}

func (c *Client) ToConfigString() string {
	return fmt.Sprintf("[Peer]\n# Name = %s\nPublicKey = %s\nAllowedIPs = %s\n\n", c.Name, c.PublicKey, c.AllowedIPs)
}

func (c *Client) ToTunnelConfigString() (string, error) {
	const TunnelTemplate = `[Interface]
PrivateKey = {{.PrivateKey}}
Address = {{.AllowedIPs}}
DNS = 8.8.8.8

[Client]
PublicKey = 4dwEjGdTNYQlQz+aOA3r+er0tOliNbI/Yv/Vp+kFYjg=
AllowedIPs = 0.0.0.0/0
Endpoint = 164.92.134.205:51820
PersistentKeepalive = 20
`
	t := template.New("Client")
	t.Parse(TunnelTemplate)

	tunnel := new(bytes.Buffer)
	err := t.Execute(tunnel, c)
	if err != nil {
		return "", err
	}
	return tunnel.String(), nil
}

func ReadConfigFile(configPath string) ([]Client, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	clients := make([]Client, 0)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "[Peer]" {
			scanner.Scan()
			ClientName := strings.Split(scanner.Text(), " = ")[1]
			scanner.Scan()
			ClientPublicKey := strings.Split(scanner.Text(), " = ")[1]
			scanner.Scan()
			ClientAllowedIPs := strings.Split(scanner.Text(), " = ")[1]

			clients = append(clients, Client{
				Name:       ClientName,
				PublicKey:  ClientPublicKey,
				AllowedIPs: ClientAllowedIPs,
			})
		}
	}
	return clients, nil
}

func SaveConfigFile(configPath string, clients []Client) error {
	const ConfigHeader = `[Interface] 
Address = 11.0.8.1/24
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
ListenPort = 51820
PrivateKey = MAAATGqhgv04dJRTjvQrjT37HbFUcZ1j2p8wD1EPYXE=

`
	file, err := os.OpenFile(configPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	content := ConfigHeader

	for i := range clients {
		content += clients[i].ToConfigString()
	}

	_, err = file.WriteString(content)
	if err != nil {
		return err
	}

	return nil
}

func GenerateNewClient(name string, clients []Client) (Client, error) {
	ip := NextAvailableIP(clients)
	kp, err := NewKeyPair()
	if err != nil {
		return Client{}, err
	}
	newClient := Client{
		Name:       name,
		PublicKey:  kp.PublicKey,
		PrivateKey: kp.PrivateKey,
		AllowedIPs: ip,
	}
	newClient.TunnelConfig = newClient.ToConfigString()
	return newClient, nil
}

func NextAvailableIP(clients []Client) string {
	ipString := strings.Split(clients[len(clients)-1].AllowedIPs, "/")[0]
	ip := net.ParseIP(ipString)
	return nextIP(ip, 1).String() + "/32"
}

func nextIP(ip net.IP, inc uint) net.IP {
	i := ip.To4()
	v := uint(i[0])<<24 + uint(i[1])<<16 + uint(i[2])<<8 + uint(i[3])
	v += inc
	v3 := byte(v & 0xFF)
	v2 := byte((v >> 8) & 0xFF)
	v1 := byte((v >> 16) & 0xFF)
	v0 := byte((v >> 24) & 0xFF)
	return net.IPv4(v0, v1, v2, v3)
}

type KeyPair struct {
	PublicKey  string
	PrivateKey string
}

func FindClienIdtByName(name string, clients []Client) (int, bool) {
	var (
		index     = 0
		foundFlag = false
	)
	for i := range clients {
		if clients[i].Name == name {
			index = i
			foundFlag = true
			break
		}
	}
	return index, foundFlag
}

func NewKeyPair() (*KeyPair, error) {
	privateKeyBytes, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		return nil, err
	}

	cmd := exec.Command("wg", "pubkey")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	if _, err := stdin.Write(privateKeyBytes); err != nil {
		return nil, err
	}
	if err := stdin.Close(); err != nil {
		return nil, err
	}

	publicKeyBytes, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	privateKey := strings.TrimRight(string(privateKeyBytes), "\n")
	publicKey := strings.TrimRight(string(publicKeyBytes), "\n")
	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}
