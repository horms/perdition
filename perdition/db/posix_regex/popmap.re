######################################################################
# popmap.re
#
# Example popmap.re
# Format: <regular expression>: <server>[:<port>]
#
# Regular expressions are extended POSIX variety
#
# Note: 
# o Anthing after a '#' on a line is treated as a comment,
#   unless the '#' is escaped (preceded by a '/')
# o A '/r', '/n' and '/0' are always treated as litereals
#   and terminate the the current line (and file in the case of '\0')
# o Anything else after a '/' is treated as a literal.
#   Thus "/#" -> '#', "//' -> '/'
#
######################################################################

^[a-k]: localhost
^[^a-k]: localhost:110
