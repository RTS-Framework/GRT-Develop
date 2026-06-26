# GRT-Develop
A package for deep customization of Gleam-RT.

## Create Instance
```go
package main

import (
    "fmt"
    "os"
    
    "github.com/RTS-Framework/GRT-Develop"
    "github.com/RTS-Framework/GRT-Develop/argument"
)

func main() {
    template, err := os.ReadFile("Gleam-RT.bin")
    checkError(err)
    
    opts := develop.Options{
        ImagePinningName:    "test.exe",
        ShieldModuleName:    "test.dll",
        ShieldEntryPoint:    0x1234,
        ShieldMemAddress:    0,
        EnableSecurityMode:  false,
        DisableDetector:     false,
        DisableWatchdog:     false,
        DisableSysmon:       false,
        NotEraseInstruction: false,
        NotAdjustProtect:    false,
        TrackCurrentThread:  false,
        
        Shield: []byte("test shield"),
        Decoy:  []byte("test decoy"),
        
        Arguments: []*argument.Arg{
            {ID: 1, Data: []byte("test1")},
            {ID: 2, Data: []byte("test2")},
        },
    }
    instance, err := develop.Instantiate(template, &opts)
    checkError(err)
    
    err = os.WriteFile("instance.bin", instance, 0600)
    checkError(err)
}

func checkError(err error) {
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}
```

## Disclaimer
This project is developed solely for security research, educational purposes, and authorized penetration testing.\
Any use for illegal activities, unauthorized access to computer systems, or malicious purposes is strictly prohibited.

By using this project, you agree that:

1. You will only use it in environments you own or have explicit authorization to test.
2. You are solely responsible for ensuring compliance with all applicable local, state, national, and international laws and regulations.
3. The authors and contributors assume no liability and are not responsible for any misuse or damage ca +used by this project.
4. You understand that unauthorized use of computer systems is a criminal offense in most jurisdictions

This software is provided "as is" without warranty of any kind, express or implied. Use at your own risk.
