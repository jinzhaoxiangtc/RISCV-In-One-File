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
    if is_hex_string(words[2]) and int(words[2], 16) < 0x80000000 and int(words[2], 16) > 0x10 :
      return

fsim = open(sys.argv[1], 'r')
ftrace = open(sys.argv[2], 'r')

startRecording = False
simInst = []

skip_ld_cmp = 0

except_pc = [0x10188, 0x1018e, 0x12628, 0x130f2, 0x11e00]
#except_pc = [0x1bbba, 0x1bbbe, 0x1bbc2, 0x1bbc6, 0x1bbca, 0x1bbce, 0x1bbd2, 0x1bbd6, 0x1bbda, 0x1bbde, 0x1bbe0, 0x1bbe2, 0x1bbe4]
#except_pc = [0x1b854, 0x1b858, 0x1b85c, 0x1b860, 0x1b864, 0x1b868, 0x1b86c, 0x1b870, 0x1b874, 0x1b878, 0x1b87a, 0x1b87c, 0x1b87e]
#0x1b046, 0x1b04a, 0x1b04e, 0x1b052, 0x1b056, 0x1b05a, 0x1b05e, 0x1b062, 0x1b066, 0x1b06a, 0x1b06c, 0x1b06e, 0x1b070]

for line in fsim :

  if startRecording :
    simInst.append(line)
  elif "Execution PC" in line :
    words = line.split()
    pc = int(words[3], 16)
    startRecording = True

# search PC in trace file
for line in ftrace :

  words = line.split()
  if is_hex_string(words[2]) and int(words[2], 16) == pc :
    break

syscall_num = 0

for line in simInst :

  if 'PC' in line :

    hasSimDst = False

    for word in line.split(' '):
      if 'PC:' in word :
        simPC = int(word.split(':')[1], 16)
      elif 'DST_VALUE:' in word :
        hasSimDst = True
        simDstValue = int(word.split(':')[1], 16)
        if simDstValue < 0 :
          simDstValue = simDstValue + 2**64
  else :
    continue

  # gain trace file PC
  line = ftrace.readline()

  if "trap_load_page_fault" in line :
    skip_exception(ftrace)
    line = ftrace.readline()

  if "trap_store_page_fault" in line :
    skip_exception(ftrace)
    line = ftrace.readline()

  print(line)
  words = line.split()

  if "trap_user_ecall" in line :
    tracePC = int(words[-1], 16)
    if syscall_num == 80 :
      # Due to fstat, don't compare the data value for the next 13 loads
      skip_ld_cmp = 13
  else :
    tracePC = int(words[3], 16)

  # check PC
  assert simPC == tracePC, "Sim PC " + hex(simPC) + " Trace PC " + hex(tracePC)

  if simPC in except_pc :
    ftrace.readline() # dump read
    continue

  if not "trap_user_ecall" in line :
    # check dest value
    if len(words) > 5 :
      # memory instructions
      if 'mem' in words :
        # load instructions
        if words[-2] == 'mem' :
          assert hasSimDst, "Trace has value, but not sim output. PC " + hex(simPC)
          traceDstValue = int(words[-3], 16)
          
          if skip_ld_cmp :
            skip_ld_cmp = skip_ld_cmp - 1
          else :
            assert simDstValue == traceDstValue, "Output are different. PC " + hex(simPC) + " Sim Dst " + hex(simDstValue) + " trace Dst " + hex(traceDstValue)
        # store instructions
        else :
          assert not hasSimDst , "Trace has no value, but sim output ahs value."
      # alu instructions
      else :
        assert hasSimDst, "Trace has value, but not sim output. PC " + hex(simPC)
        traceDstValue = int(words[-1], 16)
        if words[-2] == 'x17' :
          syscall_num = traceDstValue

        assert simDstValue == traceDstValue, "Output are different. PC " + hex(simPC) + " Sim Dst " + hex(simDstValue) + " trace Dst " + hex(traceDstValue) 
    else :
      assert not hasSimDst , "Trace has no value, but sim output has value. PC " + hex(simPC)

  skip_exception(ftrace)
