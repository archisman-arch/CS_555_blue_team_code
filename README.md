# Setup

#Standalone Python code 
python circuit.py # this includes trusted party circuit, share calculations and reconstruction circuit. 

#Project pythn folder
project.py #invokes circuit.py and calculates 1 share if run after generating teal. 
#Known issue: ALGO payment is no added, conditional check not added due to lack of time 
#To run
Take clone of https://github.com/algorand-devrel/pyteal-course
Add project.py to contracts/counter/ 
./build.sh contracts.counter.project
