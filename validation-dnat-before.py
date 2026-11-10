import ast,ipaddress,json,logging,pathlib,shlex,socket,sys,unittest
from unittest import mock
W=pathlib.Path(__file__).parent;P=W/'baseline-app.py';tree=ast.parse(P.read_text(encoding='utf8'))
names={'_parse_docker_dnat','_docker_dnat_destinations','_forward_match','_forward_shell','_forward_family_dests','public_port_forward_commands'}
ns={'ipaddress':ipaddress,'socket':socket,'shlex':shlex,'logger':logging.getLogger('baseline'),'protocol_base':lambda p:p.split('__')[0],'PUBLIC_FORWARD_L4':{'udp':('awg3',),'tcp':('xray',)}}
exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in names],type_ignores=[]),str(P),'exec'),ns)
class CurrentMainRegressions(unittest.TestCase):
 def test_tcp_and_udp_same_port_not_first_win(self):
  rules='-A DOCKER -p tcp --dport 443 -j DNAT --to-destination 172.20.0.9:443\n-A DOCKER -p udp --dport 443 -j DNAT --to-destination 172.20.0.2:443'
  self.assertNotEqual(ns['_parse_docker_dnat'](rules,'443'),'172.20.0.9:443')
 def test_wrong_or_ambiguous_container_not_selected(self):
  self.assertIsNone(ns['_parse_docker_dnat']('-A DOCKER -p udp --dport 443 -j DNAT --to-destination 172.20.0.9:443\n-A DOCKER -p udp --dport 443 -j DNAT --to-destination 172.20.0.2:443','443'))
 def test_discovery_failure_never_redirects_either_family(self):
  ssh=mock.Mock();ssh.run_sudo_command.return_value=('','nat unavailable',1)
  cmds,_=ns['public_port_forward_commands']('awg3','8443','443',container_dests=ns['_docker_dnat_destinations'](ssh,'443'))
  self.assertFalse(cmds)
 def test_cleanup_does_not_select_foreign_rules_by_port_alone(self):
  cmds,_=ns['public_port_forward_commands']('awg3','','443','8443',public_ip='203.0.113.9')
  self.assertFalse(any('grep -F -- "--dport 8443 "'in c and '--comment'not in c for c in cmds))
 def test_unresolved_dns_never_widens_scope(self):
  with mock.patch.object(socket,'getaddrinfo',side_effect=OSError()):
   cmds,_=ns['public_port_forward_commands']('awg3','8443','443',public_ip='missing.invalid',container_dests={4:'172.20.0.2:443'})
  self.assertFalse(cmds)
 def test_nonroot_sudo_shell_fix_already_in_main(self):
  cmds,_=ns['public_port_forward_commands']('awg3','8443','443',public_ip='203.0.113.9',container_dests={4:'172.20.0.2:443'})
  self.assertTrue(all(shlex.split(c)[:2]==['sh','-c']for c in cmds))
 def test_ip_recreation_scrub_already_in_main(self):
  cmds,_=ns['public_port_forward_commands']('awg3','8443','443','8443',public_ip='203.0.113.9',container_dests={4:'172.20.0.3:443'})
  self.assertTrue(any('-D PREROUTING'in c for c in cmds))
r=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(CurrentMainRegressions))
v={'main':'1d906fe40d39','tests':r.testsRun,'failures':[t.id()for t,_ in r.failures],'errors':[t.id()for t,_ in r.errors]};(W/'dnat-before.json').write_text(json.dumps(v,indent=2));assert len(r.failures)==5 and not r.errors;print(json.dumps(v))
