package main

import (
	"database/sql"
	"encoding/json"
	"porthub/internal/snapshots"
	"strconv"
	"time"
)

type mappingExecer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

const mappingTableDDL = `create table mappings(id integer primary key, name text, description text, tags text, resource_id text, service_id text, group_id text,
	edge_id text, public_ip text, target_node_id text, target_ip text, public_start int, public_end int, target_start int, target_end int,
	proto text, enabled int, acl_ids text, rate_limit_kbps int default 0, connection_limit int default 0, log_level text default 'info',
	source_mode text default 'compat', created_by text, created_at text, updated_at text)`

func insertMapping(execer mappingExecer, mapping snapshots.Mapping, createdBy string, preserveID bool) (sql.Result, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	if mapping.LogLevel == "" {
		mapping.LogLevel = "info"
	}
	if mapping.SourceMode == "" {
		mapping.SourceMode = "compat"
	}
	if mapping.CreatedAt == "" {
		mapping.CreatedAt = now
	}
	if mapping.UpdatedAt == "" {
		mapping.UpdatedAt = now
	}
	if mapping.CreatedBy == "" {
		mapping.CreatedBy = createdBy
	}
	tags, _ := json.Marshal(mapping.Tags)
	aclIDs, _ := json.Marshal(mapping.ACLIDs)
	id := 0
	if preserveID {
		id, _ = strconv.Atoi(mapping.ID)
	}
	return execer.Exec(`insert into mappings(id,name,description,tags,resource_id,service_id,group_id,edge_id,public_ip,target_node_id,target_ip,
		public_start,public_end,target_start,target_end,proto,enabled,acl_ids,rate_limit_kbps,connection_limit,log_level,source_mode,created_by,created_at,updated_at)
		values(nullif(?,0),?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, mapping.Name, mapping.Description, string(tags), mapping.ResourceID, mapping.ServiceID,
		mapping.GroupID, mapping.EdgeID, mapping.PublicIP, mapping.TargetNodeID, mapping.TargetIP, mapping.PublicStart, mapping.PublicEnd,
		mapping.TargetStart, mapping.TargetEnd, string(mapping.Protocol), boolInt(mapping.Enabled), string(aclIDs), mapping.RateLimitKbps,
		mapping.ConnectionLimit, mapping.LogLevel, mapping.SourceMode, mapping.CreatedBy, mapping.CreatedAt, mapping.UpdatedAt)
}

func updateStoredMapping(execer mappingExecer, id int, mapping snapshots.Mapping) (sql.Result, error) {
	tags, _ := json.Marshal(mapping.Tags)
	aclIDs, _ := json.Marshal(mapping.ACLIDs)
	return execer.Exec(`update mappings set name=?,description=?,tags=?,resource_id=?,service_id=?,group_id=?,edge_id=?,public_ip=?,target_node_id=?,target_ip=?,
		public_start=?,public_end=?,target_start=?,target_end=?,proto=?,enabled=?,acl_ids=?,rate_limit_kbps=?,connection_limit=?,log_level=?,source_mode=?,updated_at=? where id=?`,
		mapping.Name, mapping.Description, string(tags), mapping.ResourceID, mapping.ServiceID, mapping.GroupID, mapping.EdgeID, mapping.PublicIP, mapping.TargetNodeID,
		mapping.TargetIP, mapping.PublicStart, mapping.PublicEnd, mapping.TargetStart, mapping.TargetEnd, string(mapping.Protocol), boolInt(mapping.Enabled),
		string(aclIDs), mapping.RateLimitKbps, mapping.ConnectionLimit, mapping.LogLevel, mapping.SourceMode, time.Now().UTC().Format(time.RFC3339), id)
}
