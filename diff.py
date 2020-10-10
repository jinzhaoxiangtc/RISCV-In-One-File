#!/usr/bin/env python3

import sys

def is_hex_string(str) :

  try :
    int(str, 16)
    return True

  except ValueError :
    return False

fsim = open(sys.argv[1], 'r')
ftrace = open(sys.argv[2], 'r')

startRecording = False
simInst = []
for line in fsim :

  if startRecording :
    simInst.append(line)
  elif "The starting" in line :
    words = line.split()
    pc = int(words[4], 16)
    startRecording = True

for line in ftrace :

  words = line.split()
  if is_hex_string(words[2]) and int(words[2], 16) == pc :
    break

for line in simInst :

  if 'PC' in line :
    for word in line.split(',') :
      if 'PC' in word :
        simPC = int(word.split()[1])
  else :
    continue

  tracePC = int(ftrace.readline().split()[1], 16)

  assert simPC == tracePC, "Sim PC " + hex(simPC) + " Trace PC " + hex(tracePC)

  ftrace.readline() # dump read
