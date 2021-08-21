// YAS: Yet Another Script
package main

import (
  "fmt"
//  "log"
//  "os/exec"
  "time"
  "math/rand"
)

var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

func genRandomString(length int, charset string) string {
  b := make([]byte, length);
  for i := range b {
    b[i] = charset[seededRand.Intn(len(charset))]
  }
  return string(b);

}

func genRandomCommand() {

}

func main() {

  //cmd_jail_1 := exec.Command("./start_jails/single.exp stef")

  const charset string = "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  var cmds [3]string = [3]string{"get", "put", "save"}

  var randStr string = genRandomString(5, charset)

  fmt.Println(randStr)


  var cmd string = action + randStr + " " + randStr

  fmt.Println(cmd)

// ./sgput 

}

