package main

import (
  "fmt"
  "log"
  "os/exec"
)

// YAS: Yet Another Script

func main() {

  out, err := exec.Command("date").Output();
  if err != nil {
    log.Fatal(err)
  }
  fmt.Printf("The date is %s\n", out)

}

