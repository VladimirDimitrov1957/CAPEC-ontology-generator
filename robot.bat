java -Xmx15G -jar robot/robot.jar -vv reason --reasoner hermit --axiom-generators "SubClass EquivalentClass DisjointClasses DataPropertyCharacteristic EquivalentDataProperties SubDataProperty ClassAssertion PropertyAssertion EquivalentObjectProperty InverseObjectProperties ObjectPropertyCharacteristic SubObjectProperty ObjectPropertyRange ObjectPropertyDomain" --input results/capec.ttl --output results/capecR.ttl
