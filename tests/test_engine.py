import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from routing import Rule, Simulator, list_rules, covers, overlap, UK, JP, US, DIRECT, parse_config, assembled
from pipeline import policy_diff

class RoutingEngineTests(unittest.TestCase):
    def test_first_match_over_specificity(self):
        s=Simulator([Rule('DOMAIN-SUFFIX','example.com',UK),Rule('DOMAIN','api.example.com',JP),Rule('FINAL','',US)])
        self.assertEqual(s.match('api.example.com').policy,UK)

    def test_suffix_boundary_and_case(self):
        s=Simulator([Rule('DOMAIN-SUFFIX','paypal.com',UK),Rule('FINAL','',US)])
        self.assertEqual(s.match('API.PAYPAL.COM.').policy,UK)
        self.assertEqual(s.match('fakepaypal.com').policy,US)
        self.assertEqual(s.match('paypal.com.evil.example').policy,US)

    def test_domain_is_exact(self):
        s=Simulator([Rule('DOMAIN','api.example.com',JP),Rule('FINAL','',US)])
        self.assertEqual(s.match('api.example.com').policy,JP)
        self.assertEqual(s.match('other.api.example.com').policy,US)

    def test_keyword_semantics_only_for_simulation(self):
        s=Simulator([Rule('DOMAIN-KEYWORD','tested-keyword',JP),Rule('FINAL','',US)])
        self.assertEqual(s.match('a-tested-keyword.example').policy,JP)
        with self.assertRaises(ValueError):list_rules('DOMAIN-KEYWORD,crypto')

    def test_lan_and_geoip_position(self):
        s=Simulator([Rule('IP-CIDR','10.0.0.0/8',DIRECT),Rule('IP-CIDR6','fc00::/7',DIRECT),
                     Rule('DOMAIN-SUFFIX','tiktok.com',US),Rule('GEOIP','CN',DIRECT),Rule('FINAL','',US)])
        self.assertEqual(s.match('10.0.0.1').policy,DIRECT)
        self.assertEqual(s.match('fd00::1').policy,DIRECT)
        self.assertEqual(s.match('tiktok.com','CN').policy,US)
        self.assertEqual(s.match('new.example','CN').policy,DIRECT)
        self.assertEqual(s.match('new.example','JP').policy,US)

    def test_upstream_conflict_injections_do_not_change_fixed_priority(self):
        base=assembled()
        insert=next(i for i,r in enumerate(base) if r.category=='China DIRECT')
        injected=base[:insert]+[Rule('DOMAIN-SUFFIX',h,DIRECT) for h in ['tiktok.com','bbc.com','tver.jp','tvb.com','binance.com','paypal.com','kraken.com']]+base[insert:]
        sim=Simulator(injected)
        for host,expected in [('tiktok.com',US),('bbc.com',UK),('tver.jp',JP),('binance.com',JP),('paypal.com',UK),('kraken.com',UK)]:
            self.assertEqual(sim.match(host).policy,expected)

    def test_crypto_kraken_override(self):
        rows=assembled();position=next(i for i,r in enumerate(rows) if r.source=='rules/crypto-extra.list')
        s=Simulator(rows[:position]+[Rule('DOMAIN-SUFFIX','kraken.com',JP)]+rows[position:])
        self.assertEqual(s.match('ws-auth.kraken.com').policy,UK)

    def test_strict_parser_rejects_injection(self):
        for invalid in ['<html>login</html>','DOMAIN,example.com,PROXY','URL-REGEX,https://example.com','[General]\ndns-server = system','DOMAIN-SUFFIX,https://example.com']:
            with self.assertRaises(ValueError):list_rules(invalid)

    def test_overlap_ancestor_descendant(self):
        self.assertTrue(covers(('DOMAIN-SUFFIX','example.com'),('DOMAIN','api.example.com')))
        self.assertFalse(covers(('DOMAIN','example.com'),('DOMAIN-SUFFIX','example.com')))
        self.assertFalse(overlap(('DOMAIN-SUFFIX','example.com'),('DOMAIN-SUFFIX','notexample.com')))

    def test_update_gate_reports_direct_and_country_changes(self):
        old=[Rule('DOMAIN-SUFFIX','bank.example',UK),Rule('DOMAIN-SUFFIX','cn.example',DIRECT),Rule('FINAL','',US)]
        new=[Rule('DOMAIN-SUFFIX','bank.example',JP),Rule('DOMAIN-SUFFIX','cn.example',US),Rule('FINAL','',US)]
        changes=policy_diff(old,new)
        self.assertTrue(any(c['old']==DIRECT and c['new']==US for c in changes))
        self.assertTrue(any(c['old']==UK and c['new']==JP for c in changes))
        self.assertTrue(all(c['high_impact'] for c in changes))

    def test_new_country_rule_is_high_impact(self):
        changes=policy_diff([Rule('FINAL','',US)],[Rule('DOMAIN-SUFFIX','new.example',JP),Rule('FINAL','',US)])
        self.assertEqual(len(changes),2)

    def test_config_expansion_matches_layer_order(self):
        rows,_=parse_config()
        self.assertEqual([(r.kind,r.value,r.policy) for r in rows],[(r.kind,r.value,r.policy) for r in assembled()])

if __name__=='__main__':unittest.main()
