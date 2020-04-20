# Copyright (c) 2020 Krailerk M.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

## Import RegEx Module
import re

## Open the configuration file
f = open("doc/hello.txt")
## Print Accessible to the configuration file
print("Accessible to the configuration file")
## Save number of point header config file
datatmp = f.readlines()
## Close the configuration file
f.close()
## Print Closed to the configuration file
print("Closed to the configuration file")

## Parameter for count line of all for show
countline = 0

## Store data


## Loop for check all data
for linedata in datatmp:
    ## Count lines
    countline = countline + 1
    ## Print for show line by line and cut \n
    #print(str(countline) + linedata[:-2])

    ## Get case title
    print(re.findall("[0-9]+ \([0-9]+\) - .*" , linedata))

    ## Get NetID address
    print(re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}", linedata))

    ## Get IP address
    print(re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} \(.*\)", linedata))

    ## If for check start and end of vulnerabilities by plugin
    #if linedata.lower().find("vulnerabilities by plugin") > -1:
    #    ## Print for show if case
    #    print("IF 1 : linedata.lower()")