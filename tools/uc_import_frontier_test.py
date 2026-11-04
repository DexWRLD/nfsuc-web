import hashlib,tempfile,unittest
from pathlib import Path
import uc_import_frontier as frontier

class ImportFrontierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image=Path(r'C:\Games\Need For Speed Undercover\nfs.exe')
        cls.research=Path(r'C:\Users\999\Documents\KTA\research\undercover-phase70-legacy-crt-binding.md')
        cls.result=frontier.inspect(cls.image,cls.research)

    def test_advertised_iat_search_remains_a_bounded_negative(self):
        d=self.result
        self.assertEqual(d['advertisedImportCount'],625)
        self.assertEqual(d['advertisedActiveIatLiteralReferences'],[])
        self.assertEqual(d['activeIatCallOrThunkCandidates'],[])
        self.assertFalse(d['legitimateOrdinaryImportExecutionEstablished'])
        self.assertIn('Register-computed',d['limits'])

    def test_legacy_name_rva_is_not_an_executable_binding(self):
        d=self.result;row=next(r for r in d['legacyNameRecords'] if r['cell']==0xb61398)
        self.assertEqual(row['rawValue'],0x8aac6a)
        self.assertEqual(row['importNameAddress'],0xcaac6a)
        self.assertEqual(row['importName'],'_decode_pointer')
        self.assertFalse(row['advertisedImportDescriptorOwnsLegacyCell'])
        self.assertFalse(row['runtimeBindingVerified'])
        self.assertTrue(row['nameIdentityVerifiedFromOriginalBytes'])
        self.assertEqual(d['existingMemsetHarness']['originalThunk']['bytes'],'ff253c12b600')
        self.assertIn('FIXTURE_NOT_PROOF',d['existingMemsetHarness']['classification'])

    def test_earliest_dependencies_and_closed_provenance_gate(self):
        d=self.result
        self.assertEqual(d['earliestCrtDependencies']['cookie']['importName'],'GetSystemTimeAsFileTime')
        self.assertEqual(d['earliestCrtDependencies']['preC']['importName'],'__set_app_type')
        self.assertEqual(d['earliestCrtDependencies']['sentinel']['importName'],'_encode_pointer')
        self.assertTrue(all(not row['bindingVerified'] for row in d['earliestCrtDependencies'].values()))
        self.assertEqual(d['gate'],'BLOCKED_UNAVAILABLE_PROVIDER_PROVENANCE')
        self.assertIn('CLOSED_UNTIL_NEW',d['repeatSearchPolicy'])
        self.assertEqual(d['importedServicesExecuted'],[])
        self.assertFalse(d['protectedCodeExecuted']);self.assertFalse(d['legacyCellsChanged'])

    def test_source_hash_and_wrong_source_rejection(self):
        with tempfile.TemporaryDirectory() as temp:
            bad=Path(temp)/'wrong.exe';bad.write_bytes(b'not the reviewed image')
            with self.assertRaisesRegex(ValueError,'SHA mismatch'):frontier.inspect(bad,self.research)
        self.assertEqual(hashlib.sha256(self.image.read_bytes()).hexdigest(),frontier.SOURCE_SHA)

if __name__=='__main__':unittest.main()
