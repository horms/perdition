######################################################################
# popmap.re
#
# Example popmap.re
# Format: <regular_expression>[:] <substitution>
#
# A single colon _may_ follow a regular_expression Some ammout of white
# space must follow this colon or the regular_expression if the colon is
# omitted.  Blank lines are ignored, as is anything including and after a #
# (hash) on a line. If a \ precedes a new line then the lines will be
# concatenated.  If a \ precedes any other character, including a # (hash)
# it will be treated as a literal. Anything inside single quotes (') will
# be treated as a litreal. Anything other than a (') inside double quotes
# (") will be treated as a litreal. Whitespace in a regular_expression must
# be escaped or quoted. Whitespace in a substitution need not be escaped or
# quoted.
#
# Regular expressions are extended POSIX variety.
# There is no implcit ^ or $ around  the  regular  expressions.
#
# Substitution is of the form 
# [<username><domain_delimiter>]<server>[:<port>]
#
# Backreferences may be used by inserting $n in the substitution
# where n is in the range 1 .. 9.
#
# The regular expressions are serached in order, and the first
# matching regular expression is used.
#
######################################################################

#^[a-k]: localhost
#^[^a-k]: localhost:110
#^user: user2@localhost
#(.*)@(.*): $1_$2@localhost
