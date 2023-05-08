package registry

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

type ControllerID interface {
	fmt.Stringer
	updateVersion(uint64)
	version() uint64
}

type workerUUID struct {
	appName   string
	uuid      uuid.UUID
	kvVersion uint64
}

func (id *workerUUID) String() string {
	return id.appName + "/" + id.uuid.String()
}

func (id *workerUUID) updateVersion(rev uint64) {
	id.kvVersion = rev
}

func (id *workerUUID) version() uint64 {
	return id.kvVersion
}

func GetID(app string) ControllerID {
	return &workerUUID{
		appName: app,
		uuid:    uuid.New(),
	}
}

type activityRecord struct {
	LastActive time.Time `json:"last_active"`
}
