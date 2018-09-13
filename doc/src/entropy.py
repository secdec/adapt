#
#  Automated Dynamic Application Penetration Testing (ADAPT)
#
#  Copyright (C) 2018 Applied Visions - http://securedecisions.com
#
#  Written by Siege Technologies - http://www.siegetechnologies.com/
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

import itertools
import functools

from math import log2

'''
A tool to detect entropy of a list of strings

most of the time you'll just run entropy.entropy( <list> )
	where list is something like ['abcde','acfte', ...]
	and get back a number representing a heuristic for 
	the number of bits of shannon entropy

How it works:
For a sequence of strings, this algorithm considers how hard it would
be to guess the next string, given only the current one
However, it is just a heuristic

Steps:
1) for each adjacent pair of strings, we calculate the bitwise xnor between them
   (we also compare the first to the last)
   'aa' vs 'bc' will expand to 01100001,01100001 ^ 01100011,01100011
   for a bitwise difference (bdiff) of 00000011,00000010
   for strings with unequals lengths, we append the extra from the longer string to the shorter string.
   i.e. (comparing 'a' to 'bc' is comparing 'ac' to 'bc'
2) We collect all bdiffs, and for each bit, count the number of bdiffs where it is 1 vs 0
   Collecting these into a list of tuples
   If we have 0100,0010,0111, our zero-one tuples look like [(3,0),(1,2),(1,2),(2,1)]
3) Each per-bit count forms a small binomial distribution, for which the equation for
   shannon entropy is well known. A very random distribution like (23,22) will produce
   something close to 1. A very non-random distribution like (44,1) will produce something
   very close to 0.
4) We sum up the shannon entropy for each bit to calculate the total entropy

Caveats:
This is mostly unscientific, but seems to give a good estimate of overall randomness
We assume 8 bit characters, entering unicode strings creates undefined behavior
Small sample sizes will give poor results. Try to get more than 20 data points
May not detect large scale patterns: ["aa","bb","cc","aa","bb","cc"] may yield more entropy than it actually is
In general, kolmogorov complexity is an unsolvable problem
'''

# __ordxnor :: (Char,Char) -> [Bool]
def __ordxnor( x1,x2 ):
	x = ord(x1) ^ ord(x2)
	if( x > 2**8 ):
		print( "Non-ascii character found. This might be bad" )
	# assuming 8 bit chars
	ret = [ bool(x&(1<<i)) for i in reversed(range(0,8))]
	return ret

# __bit_diff :: (String,String)->[Bool]
# concat (map __ordxnor (zip s1 s2))
# gives bitstring diff, as a list of 8*length boolean values
def __bit_diff( s1, s2 ):
	# make the strings the same length
	s1+=(s2[len(s1):])
	s2+=(s1[len(s2):])
	assert( len( s1 ) == len( s2 ) )
	diffs = [__ordxnor(x1,x2) for (x1,x2) in zip( s1,s2 )]
	return list( itertools.chain.from_iterable( diffs ) )

# __count_diffs :: [(Int,Int)] -> [Bool] -> [(Int,Int)]
# accumulator function, if bool is false, add 1 to first in tuple
# if bool is true , add 1 to second element of tuple
# count_diffs( [(0,1),(0,1)], [True,False]) = [(0,2),(1,1)]
def __count_diffs( acc, bdiff ):
	len_diff = len( acc ) - len( bdiff )
	assert( len_diff >= 0 )
	bdiff += [0]*len_diff
	assert( len(acc) == len(bdiff ) )
	ret = []
	for ((zs,os),d) in zip( acc, bdiff ):
		if( d ):
			ret.append( (zs,os+1 ) )
		else:
			ret.append( (zs+1, os ) )
	assert( len( ret) == len( acc ) )
	return ret


# shan_ent :: [(Int,Int)] -> Float
# considers each pair of ints as a binomial distribution,
# sums entropies of each
def __shan_ent( zotuples ):
	ent = 0
	for (z,o) in zotuples:
		p = o/(z+o)
		if( p != 0 and p != 1 ):
			ent += (-p * ( log2(p) )) - ((1-p)*log2(1-p))
		# otherwise ent += 0
	return ent

'''
Takes a list of strings
returns a heuristic for the number of bits of entropy of each string
Based on the differences between successive strings
'''
def entropy( ls ):
	rot = ls[1:] + [ls[0]]
	diffs = [__bit_diff( s1,s2) for (s1,s2) in zip( ls,rot) ]
	maxbits = functools.reduce( lambda x,y:(x if x>len(y) else len(y)), diffs, 0 )
	acc = [(0,0)]*maxbits
	zotuples =  functools.reduce( __count_diffs, diffs, acc )
	return __shan_ent( zotuples )
