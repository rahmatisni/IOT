import localization as lx
import json

P=lx.Project(mode='2D',solver='LSE')


P.add_anchor('anchore_A',(0,0))
P.add_anchor('anchore_B',(5,9))
P.add_anchor('anchore_C',(10,2))

t,label=P.add_target()

t.add_measure('anchore_A',3.2323232)
t.add_measure('anchore_B',8.4141414141)
t.add_measure('anchore_C',6.234242424)

P.solve()



print(t.loc)
data = {'X': t.loc.x, 'Y' : t.loc.y}
koor = json.dumps(data)
with open('koor_user.json', 'w', encoding='utf-8') as f:
    json.dump(data, f, ensure_ascii=False, indent=4)
print (koor)