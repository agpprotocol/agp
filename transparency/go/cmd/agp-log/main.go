package main

import (
  "crypto/sha256"
  "encoding/hex"
  "encoding/json"
  "fmt"
  "os"
  "sort"
)

type Input struct {
  LogID string `json:"log_id"`
  Entries []map[string]interface{} `json:"entries"`
  ExpectedCheckpoint *string `json:"expected_checkpoint"`
}
type Err struct {
  Code string `json:"code"`
  Index interface{} `json:"index"`
}
type Receipt struct {
  Accepted bool `json:"accepted"`
  Checkpoint string `json:"checkpoint"`
  EntryCount int `json:"entry_count"`
  ErrorCodes []Err `json:"error_codes"`
  LogID string `json:"log_id"`
}
func canonical(v interface{}) []byte { b,_:=json.Marshal(v); return b }
func calcHash(e map[string]interface{}) string {
  b:=map[string]interface{}{}
  for k,v:=range e { if k!="entry_hash" { b[k]=v } }
  h:=sha256.Sum256(canonical(b))
  return "sha256:"+hex.EncodeToString(h[:])
}
func asInt(v interface{}) int {
  switch n:=v.(type) {
  case float64:
    return int(n)
  case int:
    return n
  case int64:
    return int(n)
  default:
    return -1
  }
}
func main(){
  if len(os.Args)!=3 {fmt.Fprintln(os.Stderr,"usage: agp-log INPUT OUTPUT");os.Exit(2)}
  raw,err:=os.ReadFile(os.Args[1]);if err!=nil{panic(err)}
  var in Input;if err:=json.Unmarshal(raw,&in);err!=nil{panic(err)}
  errs:=[]Err{};seen:=map[int]bool{};prev:="GENESIS"
  for expected,e:=range in.Entries {
    idx:=asInt(e["index"])
    if seen[idx] {errs=append(errs,Err{"DUPLICATE_INDEX",idx})}
    seen[idx]=true
    if idx!=expected {errs=append(errs,Err{"NON_CONTIGUOUS_INDEX",idx})}
    if p,_:=e["previous_hash"].(string);p!=prev {errs=append(errs,Err{"PREVIOUS_HASH_MISMATCH",idx})}
    computed:=calcHash(e)
    if eh,_:=e["entry_hash"].(string);eh!=computed {errs=append(errs,Err{"ENTRY_HASH_MISMATCH",idx})}
    if eh,_:=e["entry_hash"].(string);eh!="" {prev=eh}else{prev=""}
  }
  if in.ExpectedCheckpoint!=nil && prev!=*in.ExpectedCheckpoint {
    errs=append(errs,Err{"CHECKPOINT_MISMATCH",len(in.Entries)-1})
  }
  sort.Slice(errs,func(i,j int)bool{
    if errs[i].Code!=errs[j].Code{return errs[i].Code<errs[j].Code}
    return asInt(errs[i].Index)<asInt(errs[j].Index)
  })
  r:=Receipt{len(errs)==0,prev,len(in.Entries),errs,in.LogID}
  out,_:=json.Marshal(r);out=append(out,'\n')
  if err:=os.WriteFile(os.Args[2],out,0644);err!=nil{panic(err)}
}
