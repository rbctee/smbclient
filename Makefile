.DEFAULT_GOAL := build

out_dir:
	if [ ! -d out ]; then mkdir out; fi

build: out_dir
	go build -o out/smbclient cmd/main.go

clean: out_dir
	if [ -e out/smbclient ]; then rm out/smbclient; fi
