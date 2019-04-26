#! /usr/bin/env python

import argparse
import glob
import sys
import os
from shutil import copyfile

try:
  input = raw_input
except NameError:
  pass

def get_vnum(unversioned, fnames):
  vnum = 0
  while format(unversioned, vnum) in fnames and vnum < 8192:
    vnum += 1
  return vnum

def format(name, num):
  return '.{}.v{}'.format(name, num)

def versioned_write(n, data, mode='w'):
  assert not n.endswith(os.sep), "Filename must not be a directory"
  assert not os.path.isdir(n), "Filename must not be a directory"
  if os.path.exists(n):
    assert os.path.isfile(n), "Filename must be a normal file"

  dirname = os.path.dirname(n)
  fname = os.path.basename(n)

  vnum = get_vnum(fname,
                  [os.path.basename(p) for p in glob.glob(os.path.join(dirname,
                                                          '.{}.v*'.format(fname)))])
  
  versioned_fname = os.path.join(dirname, format(fname, vnum))

  assert not os.path.exists(versioned_fname), "Cowardly refusing to overwrite an existing versioned file"

  with open(n, mode) as f:
    f.write(data)

  copyfile(n, versioned_fname)

if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('file')
  args = parser.parse_args()

  versioned_write(args.file, sys.stdin.read())
