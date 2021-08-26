package ginjwt

import "fmt"

// CreateScopes will return a list of scopes allowed for creating the items that are passed in
func CreateScopes(items ...string) []string {
	s := []string{"write", "create"}
	for _, i := range items {
		s = append(s, fmt.Sprintf("create:%s", i))
	}

	return s
}

// ReadScopes will return a list of scopes allowed for creating the items that are passed in.
func ReadScopes(items ...string) []string {
	s := []string{"read"}
	for _, i := range items {
		s = append(s, fmt.Sprintf("read:%s", i))
	}

	return s
}

// UpdateScopes will return a list of scopes allowed for updating the items that are passed in.
func UpdateScopes(items ...string) []string {
	s := []string{"write", "update"}
	for _, i := range items {
		s = append(s, fmt.Sprintf("update:%s", i))
	}

	return s
}

// DeleteScopes will return a list of scopes allowed for deleting the items that are passed in.
func DeleteScopes(items ...string) []string {
	s := []string{"write", "delete"}
	for _, i := range items {
		s = append(s, fmt.Sprintf("delete:%s", i))
	}

	return s
}
