#!/usr/bin/env python3

import sys

def is_hex_string(str) :

  try :
    int(str, 16)
    return True

  except ValueError :
    return False

def skip_exception(ftrace) :

  while 1 :
    words = ftrace.readline().split()
    if is_hex_string(words[2]) and int(words[2], 16) < 0x80000000 :
      return

fsim = open(sys.argv[1], 'r')
ftrace = open(sys.argv[2], 'r')

startRecording = False
simInst = []

except_pc = [0x100f8, 0x1b046, 0x1b04a, 0x1b04e, 0x1b052, 0x1b056, 0x1b05a, 0x1b05e, 0x1b062, 0x1b066, 0x1b06a, 0x1b06c, 0x1b06e, 0x1b070]

for line in fsim :

  if startRecording :
    simInst.append(line)
  elif "The starting" in line :
    words = line.split()
    pc = int(words[4], 16)
    startRecording = True

# search PC in trace file
for line in ftrace :

  words = line.split()
  if is_hex_string(words[2]) and int(words[2], 16) == pc :
    break

for line in simInst :

  if 'PC' in line :

    hasSimDst = False

    for word in line[:-2].split(',') :
      if 'PC' in word :
        simPC = int(word.split()[1])
      elif 'DST_VALUE' in word :
        hasSimDst = True
        simDstValue = int(word.split()[1])
        if simDstValue < 0 :
          simDstValue = simDstValue + 2**64
  else :
    continue

  # gain trace file PC
  line = ftrace.readline()
  if "trap_load_page_fault" in line :
    skip_exception(ftrace)
    line = ftrace.readline()

  print(line)
  words = line.split()

  if "trap_user_ecall" in line :
    tracePC = int(words[-1], 16)
  else :
    tracePC = int(words[1], 16)

  # check PC
  assert simPC == tracePC, "Sim PC " + hex(simPC) + " Trace PC " + hex(tracePC)

  if simPC in except_pc :
    ftrace.readline() # dump read
    continue

  if not "trap_user_ecall" in line :
    # check dest value
    if len(words) > 3 :
      # memory instructions
      if 'mem' in words :
        # load instructions
        if words[-2] == 'mem' :
          assert hasSimDst, "Trace has value, but not sim output. PC " + hex(simPC)
          traceDstValue = int(words[-3], 16)
          assert simDstValue == traceDstValue, "Output are different. PC " + hex(simPC)
        # store instructions
        else :
          assert not hasSimDst , "Trace has no value, but sim output ahs value."
      # alu instructions
      else :
        assert hasSimDst, "Trace has value, but not sim output. PC " + hex(simPC)
        traceDstValue = int(words[-1], 16)
        assert simDstValue == traceDstValue, "Output are different. PC " + hex(simPC)
    else :
      assert not hasSimDst , "Trace has no value, but sim output has value. PC " + hex(simPC)

  skip_exception(ftrace)
