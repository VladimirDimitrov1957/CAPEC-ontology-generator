import urllib.request, sys, zipfile
import xml.etree.ElementTree as etree
from datetime import datetime

LS = "{http://capec.mitre.org/capec-3}"
xml_fn = "data/capec.xml"

def parseXML():
        tree = etree.parse(xml_fn)
        return tree.getroot()

def generateIndividuals(root):
        
        def generateShell(out_file):
                with open("cwe_shell.ttl", mode='r', encoding='utf-8') as in_file:
                        shell = in_file.read()
                        out_file.write(shell)
                        
        fn = "cwe.ttl"
        with open(fn, mode='w', encoding='utf-8') as out_file:
                generateShell(out_file)
                for item in root.findall(LS + "Attack_Patterns/" + LS + "Attack_Pattern/" + LS + "Related_Weaknesses/" + LS + "Related_Weakness"):
                        print("CWE-" + item.attrib["CWE_ID"])
                        out_file.write("\r:" + item.attrib["CWE_ID"] + "\r\trdf:type owl:NamedIndividual;\r\trdf:type :Weakness .")

def main():
        print("CAPEC/CWE Ontology Generator, Version 2.0")
        start = datetime.now()
        print(start)
        root = parseXML()
        generateIndividuals(root)
        print("Generation end")
        end = datetime.now()
        print(end)
        print(f"Elapsed: {end - start}")

if __name__ == "__main__":
        main()
