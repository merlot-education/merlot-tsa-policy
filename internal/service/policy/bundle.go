package policy

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"strings"
	"time"

	"gitlab.eclipse.org/eclipse/xfsc/tsa/policy/internal/storage"
)

type ZipFile struct {
	Name    string
	Content []byte
}

type Metadata struct {
	Policy struct {
		Name       string    `json:"name"`
		Group      string    `json:"group"`
		Version    string    `json:"version"`
		Repository string    `json:"repository"`
		Locked     bool      `json:"locked"`
		LastUpdate time.Time `json:"lastUpdate"`
	} `json:"policy"`
}

func (s *Service) createPolicyBundle(policy *storage.Policy) ([]byte, error) {
	var files []ZipFile

	// prepare metadata
	metadata, err := s.createMetadata(policy)
	if err != nil {
		return nil, err
	}

	files = append(files, ZipFile{
		Name:    "metadata.json",
		Content: metadata,
	})

	// prepare source code
	files = append(files, ZipFile{
		Name:    "policy.rego",
		Content: []byte(policy.Rego),
	})

	// prepare static data file
	if strings.TrimSpace(policy.Data) != "" {
		files = append(files, ZipFile{
			Name:    "data.json",
			Content: []byte(policy.Data),
		})
	}

	// prepare static data configuration file
	if strings.TrimSpace(policy.DataConfig) != "" {
		files = append(files, ZipFile{
			Name:    "data-config.json",
			Content: []byte(policy.DataConfig),
		})
	}

	return s.createZipArchive(files)
}

func (s *Service) createMetadata(policy *storage.Policy) ([]byte, error) {
	var meta Metadata
	meta.Policy.Name = policy.Name
	meta.Policy.Group = policy.Group
	meta.Policy.Version = policy.Version
	meta.Policy.Repository = policy.Repository
	meta.Policy.Locked = policy.Locked
	meta.Policy.LastUpdate = policy.LastUpdate
	return json.Marshal(meta)
}

func (s *Service) createZipArchive(files []ZipFile) ([]byte, error) {
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)
	for _, file := range files {
		f, err := zipWriter.Create(file.Name)
		if err != nil {
			return nil, err
		}

		_, err = f.Write(file.Content)
		if err != nil {
			return nil, err
		}
	}

	if err := zipWriter.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
