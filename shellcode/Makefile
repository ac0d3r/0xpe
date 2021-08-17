all: exe

exe:
	GOARCH=386 GOOS=windows go build -buildmode exe -ldflags "-s -w -H windowsgui" -o loader.exe loader.go
clean:
	rm loader.exe