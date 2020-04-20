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

## Function for check config file ready
def check_ready():
    ## Check once config ready
    try:
        ## Open the configuration file
        f = open("etc/config")
        ## Print Accessible to the configuration file
        print("Accessible to the configuration file")
        ## Save number of point header config file
        pointhead = f.read().find("##NVTECFG")
        ## Close the configuration file
        f.close()
        ## Print Closed to the configuration file
        print("Closed to the configuration file")
        ## Check config file ready
        if pointhead == 0:
            ## Print Config file ready
            print("Config file ready")
            ## Return file ready
            return True
        else:
            ## Print Config file not ready
            print("Config file not ready")
            ## Return file not ready
            return False

    except IOError:
        ## Print Not accessible the configuration file
        print("Not accessible the configuration file")
        ## Return file not ready
        return False