"""CAPEC ontology generator.

The generator downloads the current version of CAPEC List from MITRE site and then generates OWL Manchester syntax ontology.
The dictionary is downloaded as .zip file and then it is unzipped.
The ontology is generated with the file name "capec.owl".
"""

import urllib.request, re, sys, zipfile, argparse
import re, os
import xml.etree.ElementTree as etree
import lxml.etree
from datetime import datetime
from pathlib import Path 

LS = "{http://capec.mitre.org/capec-3}"
xml_fn = "data/capec.xml"

def code(s):
        return s.replace("\\", "\\\\").replace("\"", "\\\"")

def flat(s):
        return " ".join([e.strip() for e in s.strip().splitlines()])
               
def stext(s, tag):
        r = re.sub("<ns0:" + tag + " xmlns:html=\"http://www.w3.org/1999/xhtml\" xmlns:ns0=\"http://capec.mitre.org/capec-3\".*?>", "", s)
        r = re.sub("<ns0:" + tag + " xmlns:ns0=\"http://capec.mitre.org/capec-3\".*?>", "", r)
        return flat(r.replace("</ns0:" + tag + ">", ""))

class AttackPattern:
        def __init__(self, element):
                assert isinstance(element, etree.Element)
                self.element = element
                self.IRI = "CAPEC-" + element.attrib["ID"] 
                self.annotations = dict()
                self.data_facts = dict()
                self.object_facts = dict()
                self.types = set()
                
        def addType(self, aName):
                if aName == "Category":
                        self.types.add("Category")
                else:
                        self.types.add(self.element.attrib[aName])
                
        def addDataFact(self, tag, path = "", structured = False):
                for e in self.element.findall(path + LS + tag):
                        if structured:
                                value = stext(etree.tostring(e).decode('UTF-8'), tag)
                        else:
                                value = flat(e.text)
                        value = code(value)
                        if tag not in self.data_facts: self.data_facts[tag] = dict()
                        vd = self.data_facts[tag]
                        ad = dict()
                        vd[value] = ad
                        self.data_facts[tag] = vd
                        
        def addDataFactFromAttribute(self, att):
                if att in self.element.attrib:
                        value = flat(self.element.attrib[att])
                        value = code(value)
                        if att not in self.data_facts: self.data_facts[att] = dict()
                        vd = self.data_facts[att]
                        ad = dict()
                        vd[value] = ad
                        self.data_facts[att] = vd

        def addDataFactFromAttributeWithAnnotation(self, el, att, path, aName):
                for e in self.element.findall(path + LS + el):
                        value = e.attrib[att]
                        if el not in self.data_facts: self.data_facts[el] = dict()
                        fd = self.data_facts[el]
                        if value not in fd: fd[value] = dict()
                        vd = fd[value]
                        if aName not in vd: vd[aName] = set()
                        al = vd[aName]
                        if e.text:
                                aValue = flat(e.text)
                                al.add(code(aValue))
                        vd[aName] = al
                        fd[value] = vd
                        self.data_facts[el] = fd
                        
        def addDataFactWithAnnotation(self, tag, aTag, path = "", name = None, aName = None, structured = False):
                if name is None:
                        n = tag
                else:
                        n = name
                if aName is None:
                        an = aTag
                else:
                        an = aName
                for e in self.element.findall(path + LS + tag):
                        value = code(flat(e.text))
                        if n not in self.data_facts: self.data_facts[n] = dict()
                        fd = self.data_facts[n]
                        if value not in fd: fd[value] = dict()
                        vd = fd[value]
                        if an not in vd: vd[an] = set()
                        al = vd[an]
                        for ae in self.element.findall(path + LS + aTag):
                                if structured:
                                        aValue = stext(etree.tostring(ae).decode('UTF-8'), aTag)
                                else:
                                        aValue = flat(ae.text)
                                al.add(code(aValue))
                        vd[an] = al
                        fd[value] = vd
                        self.data_facts[n] = fd
        
        def addAnnotation(self, tag, name = None, path = "", structured = False):
                if name is None:
                        n = tag
                else:
                        n = name
                for e in self.element.findall(path + LS + tag):
                        if structured:
                                value = stext(etree.tostring(e).decode('UTF-8'), tag)
                        else:
                                value = flat(e.text)
                        if name not in self.annotations: self.annotations[n] = set()
                        l = self.annotations[n]
                        l.add(code(value))
                        self.annotations[n] = l
        
        def addReferences(self):
                path = LS + "References/" + LS + "Reference"
                name = "Reference"
                for e in self.element.findall(path):
                        if name not in self.annotations: self.annotations[name] = set()
                        l = self.annotations[name]
                        value = "External reference ID: " + e.attrib["External_Reference_ID"]
                        if "Section" in e.attrib: value += "\nSection: " + e.attrib["Section"]
                        l.add(code(value))
                        self.annotations[name] = l

        def addContentHistory(self):
                path = LS + "Content_History"
                e = self.element.find(path)
                el = e.find(LS + "Submission")
                if el is not None:
                        r = "Submission:"
                        for s in el.findall(LS + "Submission_Name"):
                                r += "\n\tSubmission Name: " + code(s.text)
                        for s in el.findall("Submission_Organization"):
                                r += "\n\tSubmission Organization: " + code(s.text)
                        s = el.find(LS + "Submission_Date")
                        if s is not None: r += "\n\tSubmission Date: " + code(s.text)
                        s = el.find(LS + "Submission_Comment")
                        if s is not None: r += "\n\tSubmission Comment: " + code(s.text)
                for el in e.findall(LS + "Modification"):
                        r += "\nModification:"
                        s = el.find("Modification_Name")
                        if s is not None: r += "\n\tModification Name: " + code(s.text)
                        s = el.find(LS + "Modification_Organization")
                        if s is not None: r += "\n\tModification Organization: " + code(s.text)
                        s = el.find(LS + "Modification_Date")
                        if s is not None: r += "\n\tModification Date: " + code(s.text)
                        s = el.find(LS + "Modification_Importance")
                        if s is not None: r += "\n\tModification Importance: " + code(s.text)
                        s = el.find(LS + "Modification_Comment")
                        if s is not None: r += "\n\tModification Comment: " + code(s.text)
                for el in e.findall(LS + "Contribution"):
                        r += "\nContribution:"
                        s = el.find("Contribution_Name")
                        if s is not None: r += "\n\tContribution Name: " + code(s.text)
                        s = el.find(LS + "Contribution_Organization")
                        if s is not None: r += "\n\tContribution Organization: " + code(s.text)
                        s = el.find(LS + "Contribution_Date")
                        if s is not None: r += "\n\tContribution Date: " + code(s.text)
                        s = el.find(LS + "Contribution_Comment")
                        if s is not None: r += "\n\tContribution Comment: " + code(s.text)
                        r += "\n\tType: " + code(el.attrib["Type"])
                for el in e.findall(LS + "Previous_Entry_Name"):
                        r += "\nPrevious Entry Name: " + code(el.text)
                        r += "\n\tDate: " + el.attrib["Date"]
                self.annotations["Content_History"] = {r}

        def addObjectFact(self, path, oName, cName, cADict):
                count = 0
                for e in self.element.findall(path + LS + cName):
                        if oName not in self.object_facts: self.object_facts[oName] = set()
                        ol= self.object_facts[oName]
                        name = self.IRI + "_" + cName + str(count)
                        ind = Individual(name)
                        ind.addType(cName)
                        for k, v in cADict.items():
                                if k in e.attrib: ind.addDataFact(v, code(e.attrib[k]))
                        ol.add(name)
                        self.object_facts[oName] = ol
                        count += 1

        def addObjectFactWithAnnotation(self, path, oName, cName, cADict = {}, cSDict = {}, cANDict = {}, references = False, note = False):
                count = 0
                for e in self.element.findall(path):
                        if oName not in self.object_facts: self.object_facts[oName] = set()
                        ol = self.object_facts[oName]
                        name = self.IRI + "_" + cName + str(count)
                        ind = Individual(name)
                        ind.addType(cName)
                        for k, v in cADict.items():
                                if k in e.attrib: ind.addDataFact(v, code(e.attrib[k]))
                        for k, v in cSDict.items():
                                for el in e.findall(LS + k):
                                        if v == "Observed_Example_Reference":
                                                if el.text.startswith("CVE"):
                                                        ind.addObjectFact(v, "cve:" + el.text)
                                                else:
                                                        ind.addAnnotation("Reference", el.text)
                                        else:
                                                ind.addDataFact(v, code(el.text))
                        for k, v in cANDict.items():
                                for el in e.findall(LS + k):
                                        if k == "Technique" and "CAPEC_ID" in el.attrib:
                                                ind.addObjectFactWithAnnotations(k, "CAPEC-" + el.attrib["CAPEC_ID"], v[0], code(stext(etree.tostring(el).decode('UTF-8'), k)))
                                                continue
                                        if v[1]:
                                                ind.addAnnotation(v[0], code(stext(etree.tostring(el).decode('UTF-8'), k)))
                                        else:
                                                ind.addAnnotation(v[0], code(el.text))
                        if note: ind.addAnnotation("Note_Description", code(stext(etree.tostring(e).decode('UTF-8'), "Note")))
                        ol.add(name)
                        self.object_facts[oName] = ol
                        if references:
                                for ref in e.findall(LS + "References/" + LS + "Reference"):
                                        an = "External reference ID: " + ref.attrib["External_Reference_ID"]
                                        if "Section" in ref.attrib: an += "\nSection: " + ref.attrib["Section"]
                                        ind.addAnnotation("Reference", code(an))
                        count += 1
                        
        def addCWE(self):
                els = self.element.findall(LS + "Related_Weaknesses/" + LS + "Related_Weakness")
                if not els: return 
                oName = "Related_Weakness"
                if oName not in self.object_facts: self.object_facts[oName] = set()
                ol = self.object_facts[oName]
                for e in  els:
                        ol.add("cwe:CWE-" + e.attrib["CWE_ID"])
                self.object_facts[oName] = ol

        def addExcludeRelated(self, category):
                oName = "Exclude_Related"
                if oName not in self.object_facts: self.object_facts[oName] = set()
                ol = self.object_facts[oName]
                ol.add("CAPEC-" + category)
                self.object_facts[oName] = ol

        def tostring(self):
                r = "\r### " + self.IRI + "\n:" + self.IRI + "\r\trdf:type owl:NamedIndividual;\r\t:ID " + self.element.attrib["ID"]
                for t in self.types:
                        r += ";\r\trdf:type :" + t
                if self.annotations:
                        for a, l in self.annotations.items():
                                for v in l:
                                        r += ";\r\t:" + a + " \"" + v + "\""
                if self.data_facts:
                        for f, fd in self.data_facts.items():
                                for fv, ad in fd.items():
                                        for a, avl in ad.items():
                                                for av in avl:
                                                         r += ";\r\t:" + a + " \"" + av + "\""
                                        r += ";\r\t:" + f + " \"" + fv + "\""
                if self.object_facts:
                        for f, fl in self.object_facts.items():
                                for ind in fl:
                                        value = ""
                                        if ":" not in ind: value = ":"
                                        value += ind
                                        r += ";\r\t:" + f + " " + value
                return r + "."
        
        def addMembers(self, relationships = False):
                if relationships:
                        path = LS + "Relationships"
                else:
                        path = LS + "Members"
                e = self.element.find(path)
                if e is not None:
                        for el in e.findall(LS + "Member_Of"):
                                oName = "Member_Of"
                                if oName not in self.object_facts: self.object_facts[oName] = set()
                                ol = self.object_facts[oName]
                                ol.add("CAPEC-" + str(el.attrib["CAPEC_ID"]))
                                self.object_facts[oName] = ol
                        for el in e.findall(LS + "Has_Member"):
                                oName = "Has_Member"
                                if oName not in self.object_facts: self.object_facts[oName] = set()
                                ol = self.object_facts[oName]
                                ol.add("CAPEC-" + str(el.attrib["CAPEC_ID"]))
                                self.object_facts[oName] = ol
                                
        def addRelatedAttackPatterns(self):
                path = LS + "Related_Attack_Patterns"
                e = self.element.find(path)
                if e is not None:
                        for el in e.findall(LS + "Related_Attack_Pattern"):
                                oName = el.attrib["Nature"]
                                if oName not in self.object_facts: self.object_facts[oName] = set()
                                ol = self.object_facts[oName]
                                ol.add("CAPEC-" + str(el.attrib["CAPEC_ID"]))
                                self.object_facts[oName] = ol
                                if oName == "ChildOf":
                                        for ex in el.findall(LS + "Exclude_Related"):
                                                self.addExcludeRelated(ex.attrib["Exclude_ID"])                                
        def addContent(self, capecID):
                oName = "Has_Member"
                if oName not in self.object_facts: self.object_facts[oName] = set()
                ol = self.object_facts[oName]
                ol.add("CAPEC-" + capecID)
                self.object_facts[oName] = ol
                
class Individual:
        extend = set()
        def __init__(self, name):
                self.name = name
                self.types = set()
                self.annotations = dict()
                self.data_facts = dict()
                self.object_facts = dict()
                self.object_facts_with_annotations = dict()
                Individual.extend.add(self)
        def addType(self, t):
                self.types.add(t)
        def addDataFact(self, d, v):
                if d not in self.data_facts: self.data_facts[d] = set()
                ds = self.data_facts[d]
                ds.add(v)
                self.data_facts[d] = ds
        def addObjectFact(self, d, v):
                if d not in self.object_facts: self.object_facts[d] = set()
                ds = self.object_facts[d]
                ds.add(v)
                self.object_facts[d] = ds
        def addObjectFactWithAnnotations(self, d, v, an, av):
                if d not in self.object_facts_with_annotations: self.object_facts_with_annotations[d] = set()
                ds = self.object_facts_with_annotations[d]
                ds.add((v, an, av))
                self.object_facts_with_annotations[d] = ds
        def addAnnotation(self, a, v):
                if a not in self.annotations: self.annotations[a] = set()
                s = self.annotations[a]
                s.add(v)
                self.annotations[a] = s
        def tostring(self):
                r = "\r###  " + self.name + "\n:" + self.name + "\r\trdf:type owl:NamedIndividual" 
                if self.types:
                        for t in self.types:
                                r += ";\r\trdf:type :" + t
                if self.annotations:
                        for a, av in self.annotations.items():
                                for l in av:
                                        r += ";\r\t:" + a + " \"" + l + "\""
                if self.data_facts:
                        for f, fv in self.data_facts.items():
                                for v in fv:
                                        if f == "Step":
                                                 r += ";\r\t:" + f + " \"" + v + "\"^^xsd:positiveInteger"
                                        else:
                                                r += ";\r\t:" + f + " \"" + v + "\""
                if self.object_facts:
                        for f, fv in self.object_facts.items():
                                for v in fv:
                                        if f == "CPE_ID":
                                                r += ";\r\tcpe:CPE_ID " + convert_fs_to_compressed_uri(v)
                                        else:
                                                r += ";\r\t:" + f + " :" + v
                if self.object_facts_with_annotations:
                        for f, fv in self.object_facts_with_annotations.items():
                                for v in fv:
                                        r += ";\r\t:" + v[1] + " \"" + v[2] + "\";\r\t:" + f + " :" + v[0]
                return r + "."

def downloadCAPEC():
        url = "http://capec.mitre.org/data/archive/capec_latest.zip"
        fileName = "data/capec_latest.zip"
        with urllib.request.urlopen(url) as response:
                contents = response.read()
                with open(fileName, mode='wb') as out_file:
                        out_file.write(contents)
        with zipfile.ZipFile(fileName, 'r') as zip_ref:
            zip_ref.extractall(path="data")
            xml = os.replace("data/" + zip_ref.namelist()[0], "data/capec.xml")

def parseXML():
        tree = etree.parse(xml_fn)
        return tree.getroot()

def generateAttackPatternIndividual(item, out_file):
        attackPattern = AttackPattern(item)
        attackPattern.addAnnotation("Description", name = "Attack_Pattern_Description", structured = True)
        attackPattern.addAnnotation("Extended_Description", structured = True)
        attackPattern.addDataFactWithAnnotation("Term", "Description", path = LS + "Alternate_Terms/" + LS + "Alternate_Term/", name = "Alternate_Term", aName = "Alternate_Term_Description", structured = True)
        attackPattern.addDataFact("Likelihood_Of_Attack")
        attackPattern.addDataFact("Typical_Severity")
        attackPattern.addDataFactFromAttribute("Name")
        attackPattern.addRelatedAttackPatterns()
        attackPattern.addType("Abstraction")
        attackPattern.addType("Status")
        ce = {"Step":"Step", "Phase":"Phase"}
        can = {"Description":("Attack_Step_Description", True), "Technique":("Technique_Description", True)}
        attackPattern.addObjectFactWithAnnotation(LS + "Execution_Flow/" + LS + "Attack_Step", "Execution_Flow", "Attack_Step", cSDict = ce, cANDict = can)
        attackPattern.addAnnotation("Prerequisite", path = LS + "Prerequisites/", structured = True)
        attackPattern.addDataFactFromAttributeWithAnnotation("Skill", "Level", LS + "Skills_Required/", "Skill_Description")
        attackPattern.addAnnotation("Resource", path = LS + "Resources_Required/", structured = True)
        attackPattern.addAnnotation("Indicator", path = LS + "Indicators/", structured = True)
        ca = {"Consequence_ID":"Consequence_ID"}
        ce = {"Scope":"Scope", "Impact":"Impact", "Likelihood":"Likelihood"}
        can = {"Note":("Consequence_Note", True)}
        attackPattern.addObjectFactWithAnnotation(LS + "Consequences/" + LS + "Consequence", "Consequence", "Consequence", cADict = ca, cSDict = ce, cANDict = can)
        attackPattern.addAnnotation("Mitigation", path = LS + "Mitigations/", structured = True)
        attackPattern.addAnnotation("Example", path = LS + "Example_Instances/", structured = True)
        attackPattern.addCWE()
        ca = {"Taxonomy_Name":"Taxonomy_Name"}
        ce = {"Entry_ID":"Entry_ID", "Entry_Name":"Entry_Name", "Mapping_Fit":"Mapping_Fit"}
        attackPattern.addObjectFactWithAnnotation(LS + "Taxonomy_Mappings/" + LS + "Taxonomy_Mapping", "Taxonomy_Mapping", "Taxonomy_Mapping", cADict = ca, cSDict = ce)
        attackPattern.addReferences()
        ca = {"Type":"Type"}
        attackPattern.addObjectFactWithAnnotation(LS + "Notes/" + LS + "Note", "Note", "Note", cADict = ca, note = True)
        attackPattern.addContentHistory()
        attackPattern.addRelatedAttackPatterns()
        out_file.write(attackPattern.tostring())

def generateCategoryIndividual(item, out_file):
        attackPattern = AttackPattern(item)
        attackPattern.addType("Category")
        attackPattern.addType("Status")
        attackPattern.addDataFactFromAttribute("Name")
        attackPattern.addAnnotation("Summary")
        attackPattern.addMembers(relationships = True)
        ca = {"Taxonomy_Name":"Taxonomy_Name"}
        ce = {"Entry_ID":"Entry_ID", "Entry_Name":"Entry_Name", "Mapping_Fit":"Mapping_Fit"}
        attackPattern.addObjectFactWithAnnotation(LS + "Taxonomy_Mappings/" + LS + "Taxonomy_Mapping", "Taxonomy_Mapping", "Taxonomy_Mapping", cADict = ca, cSDict = ce)
        attackPattern.addReferences()
        ca = {"Type":"Type"}
        attackPattern.addObjectFactWithAnnotation(LS + "Notes/" + LS + "Note", "Note", "Note", cADict = ca, note = True)
        attackPattern.addContentHistory()
        out_file.write(attackPattern.tostring())

def generateViewIndividual(item, root, out_file):
        attackPattern = AttackPattern(item)
        attackPattern.addType("Type")
        attackPattern.addType("Status")
        attackPattern.addDataFactFromAttribute("Name")
        attackPattern.addAnnotation("Objective")
        attackPattern.addDataFactWithAnnotation("Type", "Description", path = LS + "Audience/" + LS + "Stakeholder/", name = "Audience", aName = "Audience_Description")
        attackPattern.addMembers()
        attackPattern.addAnnotation("Filter")
        f = item.find(LS + "Filter")
        if f is not None:
                n = int(item.attrib["ID"])
                if n == 2000:
                        for ap in root.findall(LS + "Attack_Patterns/" + LS + "Attack_Pattern"): attackPattern.addContent(ap.attrib["ID"])
                        for c in root.findall(LS + "Categories/" + LS + "Category"): attackPattern.addContent(c.attrib["ID"])
                        for v in root.findall(LS + "Views/" + LS + "View"): attackPattern.addContent(v.attrib["ID"])
                elif n == 282:
                        for ap in root.findall(LS + "Attack_Patterns/" + LS + "Attack_Pattern"):
                                if "Abstraction" in ap.attrib and ap.attrib["Abstraction"] == "Meta": attackPattern.addContent(ap.attrib["ID"])
                elif n == 283:
                        for ap in root.findall(LS + "Attack_Patterns/" + LS + "Attack_Pattern"):
                                if "Abstraction" in ap.attrib and ap.attrib["Abstraction"] == "Standard": attackPattern.addContent(ap.attrib["ID"])
                elif n == 284:
                        for ap in root.findall(LS + "Attack_Patterns/" + LS + "Attack_Pattern"):
                                if "Abstraction" in ap.attrib and ap.attrib["Abstraction"] == "Detailed": attackPattern.addContent(ap.attrib["ID"])
                elif n == 333:
                        for ap in root.findall(LS + "Attack_Patterns/" + LS + "Attack_Pattern"):
                                tm = ap.find(LS + "Taxonomy_Mappings")
                                if tm is None: continue
                                found = False
                                for t in tm.findall(LS + "Taxonomy_Mapping"):
                                        if t.attrib["Taxonomy_Name"] == "WASC":
                                                found = True
                                                break
                                if found: attackPattern.addContent(ap.attrib["ID"])
                elif n == 483:
                        for ap in root.findall(LS + "Attack_Patterns/" + LS + "Attack_Pattern"):
                                if "Status" in ap.attrib and ap.attrib["Status"] == "Deprecated": attackPattern.addContent(ap.attrib["ID"])
                        for c in root.findall(LS + "Categories/" + LS + "Category"):
                                if "Status" in c.attrib and c.attrib["Status"] == "Deprecated": attackPattern.addContent(c.attrib["ID"])
                        for v in root.findall(LS + "Views/" + LS + "View"):
                                if "Status" in v.attrib and v.attrib["Status"] == "Deprecated": attackPattern.addContent(v.attrib["ID"])
                elif n == 553:
                        for ap in root.findall(LS + "Attack_Patterns/" + LS + "Attack_Pattern"):
                                if int(ap.attrib["ID"]) in (187, 498, 604, 605, 606, 608, 609, 610, 612, 613, 614, 615, 617, 618, 619, 621, 622, 623, 625, 626, 627, 628, 629): attackPattern.addContent(ap.attrib["ID"])
                elif n == 658:
                        for ap in root.findall(LS + "Attack_Patterns/" + LS + "Attack_Pattern"):
                                tm = ap.find(LS + "Taxonomy_Mappings")
                                if tm is None: continue
                                found = False
                                for t in tm.findall(LS + "Taxonomy_Mapping"):
                                        if t.attrib["Taxonomy_Name"] == "ATTACK":
                                                found = True
                                                break
                                if found: attackPattern.addContent(ap.attrib["ID"])
                elif n == 659:
                        for ap in root.findall(LS + "Attack_Patterns/" + LS + "Attack_Pattern"):
                                tm = ap.find(LS + "Taxonomy_Mappings")
                                if tm is None: continue
                                found = False
                                for t in tm.findall(LS + "Taxonomy_Mapping"):
                                        if t.attrib["Taxonomy_Name"] == "OWASP Attacks":
                                                found = True
                                                break
                                if found: attackPattern.addContent(ap.attrib["ID"])
        attackPattern.addReferences()
        ca = {"Type":"Type"}
        attackPattern.addObjectFactWithAnnotation(LS + "Notes/" + LS + "Note", "Note", "Note", cADict = ca, note = True)
        attackPattern.addContentHistory()
        out_file.write(attackPattern.tostring())

def generateIndividuals(root):

        def generateShell():
                def collectExternalReferences():
                        print("Generate external references")
                        externalreferences = root.find(LS + "External_References")
                        r = ""
                        if externalreferences is not None:
                                for e in externalreferences.findall(LS + "External_Reference"):
                                        r += ":External_Reference \""
                                        if "Reference_ID" in e.attrib: r += "\nReference_ID: " + e.attrib["Reference_ID"]
                                        for a in e.findall(LS + "Author"): r += "\nAuthor: " + code(a.text)
                                        r += "\nTitle: " + code(e.find(LS + "Title").text)
                                        ed = e.find(LS + "Edition")
                                        if ed is not None: r += "\nEdition: " + code(ed.text)
                                        p = e.find(LS + "Publication")
                                        if p is not None: r += "\nPublication: " + code(p.text)
                                        p = e.find(LS + "Publication_Year")
                                        if p is not None: r += "\nPublication year: " + code(p.text)
                                        p = e.find(LS + "Publication_Month")
                                        if p is not None: r += "\nPublication month: " + code(p.text)
                                        p = e.find(LS + "Publication_Day")
                                        if p is not None: r += "\nPublication day: " + code(p.text)
                                        p = e.find(LS + "Publisher")
                                        if p is not None: r += "\nPublisher: " + code(p.text)
                                        url = e.find(LS + "URL")
                                        if url is not None: r += "\nURL: " + code(url.text)
                                        url = e.find(LS + "URL_Date")
                                        if url is not None: r += "\nURL date: " + code(url.text)
                                        r += "\"^^rdfs:Literal ;\r"
                                return r
                
                with open("shell.ttl", mode='r', encoding='utf-8') as in_file:
                        shell = in_file.read()
                        name = root.attrib["Name"]
                        name = "" if name is None else name
                        shell = shell.replace("NAME", name)
                        version = root.attrib["Version"]
                        version = "" if version is None else version
                        shell = shell.replace("VERSION", version)
                        date = root.attrib["Date"]
                        date = "" if date is None else date
                        shell = shell.replace("DATE", date)
                        shell = shell.replace(":External_Reference \"\"^^rdfs:Literal ;\n", collectExternalReferences())
                        out_file.write(shell)                                                       
                out_file.write("\n")
                
        print("Processing started")

        p = Path("results")
        try:
                p.mkdir()
        except FileExistsError as exc:
                print(exc)
       
        fn = "results/capec.ttl"
        with open(fn, mode='w', encoding='utf-8') as out_file:
                
                generateShell()

                print("Generate attack patterns")
                attackPatterns = root.find(LS + "Attack_Patterns")
                for item in attackPatterns.findall(LS + "Attack_Pattern"):
                        print("CAPEC-" + item.attrib["ID"])
                        generateAttackPatternIndividual(item, out_file)

                print("Generate categories")
                categories = root.find(LS + "Categories")
                for item in categories.findall(LS + "Category"):
                        print("CAPEC-" + item.attrib["ID"])
                        generateCategoryIndividual(item, out_file)

                print("Generate views")
                views = root.find(LS + "Views")
                for item in views.findall(LS + "View"):
                        print("CAPEC-" + item.attrib["ID"])
                        generateViewIndividual(item, root, out_file)
                        
                for i in Individual.extend:
                        out_file.write(i.tostring())
        print("Processing finished")

def main(download):
        print("CAPEC Ontology Generator, Version 6.0")
        start = datetime.now()
        print(start)
        if download:
                print("Download CAPEC List")
                downloadCAPEC()
        xml_file = lxml.etree.parse("data/capec.xml")
        xml_validator = lxml.etree.XMLSchema(file="data/ap_schema_v3.5.xsd")
        if not xml_validator.validate(xml_file):
                print("CAPEC List contents is not valid!")
                print(xml_validator.error_log)
                return
        xml_file = None
        xml_validator = None
        root = parseXML()
        generateIndividuals(root)
        print("Generation end")
        end = datetime.now()
        print(end)
        print(f"Elapsed: {end - start}")

if __name__ == "__main__":
        parser = argparse.ArgumentParser()
        parser.add_argument('-d', '--download', action="store_true", help='download input from the Web')
        args = parser.parse_args()
        main(args.download)
