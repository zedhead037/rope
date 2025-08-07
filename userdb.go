package main

import (
	"bufio"
	"errors"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type UserDatabase map[string]string

func loadUserDatabase(p string) (UserDatabase, error) {
	f, err := os.Open(p)
	if err != nil { return nil, err }
	br := bufio.NewReader(f)
	res := make(map[string]string, 0)
	for {
		l, err := br.ReadString('\n')
		if err != nil { break }
		ll := strings.TrimSpace(l)
		rr := strings.SplitN(ll, ":", 2)
		res[strings.TrimSpace(rr[0])] = strings.TrimSpace(rr[1])
	}
	return res, nil
}

var ErrUserNotFound = errors.New("user not found")
var ErrPasswordMismatch = errors.New("password mismatch")

func (db UserDatabase) Check(username string, passwd string) error {
	k, ok := db[username]
	if !ok { return ErrUserNotFound }
	return bcrypt.CompareHashAndPassword([]byte(k), []byte(passwd))
}

