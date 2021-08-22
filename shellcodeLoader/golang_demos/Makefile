all: 0

0:
	GOARCH=386 GOOS=windows go build -buildmode exe -ldflags "-s -w -H windowsgui" -o 0x00.exe 0x00/0x00.go
1:
	GOARCH=386 GOOS=windows go build -buildmode exe -ldflags "-s -w -H windowsgui" -o 0x01.exe 0x01/0x01.go
2:
	GOARCH=386 GOOS=windows go build -buildmode exe -ldflags "-s -w -H windowsgui" -o 0x02.exe 0x02/0x02.go

clean:
	rm 0x0*.exe