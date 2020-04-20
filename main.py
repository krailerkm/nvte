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

from datetime import datetime

try:
    ## Open a file config
    fileconfig = open("etc/config", "r")

    ## Debug print step
    print(str(datetime.now()) + " Successful read config file.")

    ## Store all config
    dataconfig = fileconfig.readlines()

    ## Debug print all file config
    print(str(datetime.now()) + " " + str(dataconfig))

except ValueError:
    print(str(datetime.now()) + "Error read config file.")

## Set deafult i=0 first
i = 0
## Set default string to open file va
partvaf = str()
# loop for read all config
for i in range(len(dataconfig)):
    # Tmp store file config in line
    tmpconffile = dataconfig[i].split("=")
    # Debug print tmpconffile
    #print tmpconffile
    # Check inputfile or not
    if "inputfile" in tmpconffile:
        # Set partvaf to parth in file config
        partvaf = tmpconffile[1]
# Open file va scan to process
fileva = open(partvaf, "r")
# Store all va file
datava = fileva.readlines()
# Debug print all va file
#print datava
# Set deafult i=0 first
i = 0
# Vulnerabilities List Store
vulner = list()
# Vulnerabilities Number List Store
vulnernum = list()
# Number of Vulnerabilities
numvulner = 0
# Risk Count Boolean
countrisk = False
# Hosts Count Boolean
counthosts = False
# Count Risk Host
rhostcount = 0
# Count Page
pagecount = 0
# Store sub data in format
storesubdata = list()
# Store sub ip in format
storehostipdata = str()
# Store sub data in format
storehostipdata = str()
# Vulnerabilities Name
storevulndata = str()
# Risk Name
storeriskdata = str()
# Start file
fout = open('output.csv', 'w')
# loop for read all config
for i in range(len(datava)):
    # Debug print all line datava
    print(datava[i])
    # Tmp space cut
    tmpspace = datava[i][2:].split(" ")
    # Tmp dot cut
    tmpdot = datava[i][2:].split(".")
    # Debug Vulnerabilities Number
    #print tmpspace[0]
    # Debug Status Risk
    #print countrisk
    # Debug Status Hosts
    #print counthosts
    # Find lange of string in Line
    langedatava = len(datava[i])
    # Set page number
    pagenum = datava[i].find("Page")
    # Select show line status page current
    if pagenum > -1 and datava[i][pagenum-3:pagenum-2] == "*":
        # Page Count
        pagecount+=1
        # Show status page current
        print(datava[i][pagenum:langedatava-2])
    # Select Same Vulnerabilities in List
    elif tmpspace[0] in vulnernum and tmpspace[1][:1] == "(":
        # Debug Vulnerabilities in List
        #print datava[i][2:langedatava-2]
        # Debug storesubdata
        print(storesubdata)
        # Select first runing program
        if storesubdata == list() and storehostipdata == str() and storeriskdata == str() and storevulndata == str():
            # Debug start program
            print("-*-*-Start Report-*-*-")
        else:
            # Set loop for print csv
            loopc = 2
            # Loop for print to csv
            while loopc < len(storesubdata):
                # Tmp save data to csv
                tmpcsv = storesubdata[0] + "," + storesubdata[1] + "," + storesubdata[loopc] + "\n"
                # Write to file
                fout.write(tmpcsv)
                # Debug print to csv
                print(tmpcsv)
                # Count loop up
                loopc += 1
            # Debug save config
            print("-*-*-Save Config-*-*-")
        # Set Risk Count Boolean off
        countrisk = False
        # Set Hosts Count Boolean on
        counthosts = False
        # Clear store sub data in format
        storesubdata = list()
        # Store all data in format
        storealldata = list()
        # Store sub data in format
        storesubdata = list()
        # Store sub data in format
        storehostipdata = str()
        # Vulnerabilities Name
        storevulndata = str()
        # Risk Name
        storeriskdata = str()
        # Store data to storevulndata
        storevulndata = datava[i][2:langedatava - 2]
        # Debug Vulnerabilities in storevulndata
        print(storevulndata)
        # Store to vuln storesubdata
        storesubdata.append(storevulndata)
    # Select Risk Count Boolean on
    elif "Risk Factor" in datava[i]:
        # Set Risk Count Boolean on
        countrisk = True
        # Find lange of string 2 in Line
        langedatava2 = len(datava[i+2])
        # Debug Risk
        #print datava[i+2][2:langedatava2-2]
        # Store data to storeriskdata
        storeriskdata = datava[i+2][2:langedatava2-2]
        # Debug Risk from storeriskdata
        print(storeriskdata)
        # Store Risk to storesubdata
        storesubdata.append(storeriskdata)
    # Select Hosts Count Boolean on
    elif "Hosts" in datava[i]:
        # Set Hosts Count Boolean on
        counthosts = True
        # Find lange of string 2 in Line
        #langedatava2 = len(datava[i+2])
        # Debug Hosts
        #print datava[i+2][2:langedatava2-2]
    # Select IP Host from on line string
    elif (counthosts == True) and (datava[i].count(".") == 3) and tmpdot[0].isdigit() and tmpdot[1].isdigit() and tmpdot[2].isdigit():
        # Count rhostcount
        rhostcount+=1
        # Debig Show IP
        #print tmpspace[0]
        # Store data to storesubdata
        storehostipdata = datava[i][2:langedatava-2]
        # Store ip to store subdata
        storesubdata.append(storehostipdata)
        # Debig Show IP from list
        print(storehostipdata)
    # Select Store Vulnerabilities to list
    elif tmpspace[0].isdigit() and (tmpspace[1].isdigit() != True):
        # Debug Vulnerabilities Line
        #print datava[i][2:langedatava-2]
        # Store Vulnerabilities to List
        vulner.append(datava[i][2:langedatava-2])
        # Store Vulnerabilities Number to List
        vulnernum.append(tmpspace[0])
        # Debug Vulnerabilities Store Line
        #print vulner[numvulner]
        # Count Vulnerabilities Number
        numvulner+=1
    # Select End of Report
    elif "This is a report from the Nessus Vulnerability Scanner" in datava[i]:
        # Debug storesubdata
        print(storesubdata)
        # Set loop for print csv
        loopc = 2
        # Loop for print to csv
        while loopc < len(storesubdata):
            # Tmp save data to csv
            tmpcsv = storesubdata[0] + "," + storesubdata[1] + "," + storesubdata[loopc] + "\n"
            # Write to file
            fout.write(tmpcsv)
            # Debug print to csv
            print(tmpcsv)
            # Count loop up
            loopc += 1
        # Debug save config
        print("-*-*-Save Config-*-*-")
        # Print Show End of Report
        print("-*-*-End Report-*-*-")
# Print Summary
print("====================== Summary =======================\nPage: " + str(pagecount) +"\nNumber Host Risk: " + str(rhostcount) + "\nVulnerabilities: " + str(numvulner))
# Close file
fout.close()
