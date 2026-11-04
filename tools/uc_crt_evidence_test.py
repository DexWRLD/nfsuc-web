import hashlib,json,tempfile,unittest
from pathlib import Path
import uc_crt_evidence as crt

class CrtEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image=Path(r'C:\Games\Need For Speed Undercover\nfs.exe')
        cls.research=Path(r'C:\Users\999\Documents\KTA\research\undercover-phase69-provider-provenance.md')
        cls.binding,cls.order=crt.inspect(cls.image,cls.research)

    def test_active_import_identity_is_separate_from_legacy_binding(self):
        b=self.binding;self.assertEqual(b['descriptor']['importCount'],171)
        self.assertEqual(b['descriptor']['address'],0x22ced83)
        for row in b['providers']:
            self.assertEqual(row['dll'],'MSVCR80.dll')
            self.assertEqual(row['activeSection']['name'],'.securom')
            self.assertEqual(row['legacySection']['name'],'.rdata')
            self.assertFalse(row['legacySection']['writable'])
            self.assertEqual(row['tableIndex'],row['index'])
            self.assertFalse(row['runtimeBindingVerified'])
            self.assertIsNone(row['loaderResolvedExternalService'])
        decode=next(p for p in b['providers'] if p['symbol']=='_decode_pointer')
        self.assertEqual((decode['legacyCell'],decode['legacyFileValue'],decode['activeImportCell']),(0xb61398,0x8aac6a,0x22ce05f))

    def test_no_relocation_or_bound_import_metadata_explains_the_legacy_cells(self):
        self.assertTrue(self.binding['relocationsStripped'])
        for directory in ['5','11','13']:
            self.assertEqual(self.binding['directories'][directory],dict(rva=0,size=0))
        self.assertIsNone(self.binding['provenLegacyWriter'])
        self.assertIsNone(self.binding['provenLoaderCopy'])
        self.assertIn('Computed/unindexed writes',self.binding['scanLimits'])

    def test_original_cookie_and_conditional_initializer_order(self):
        order=self.order;ins={i['address']:i for region in order['regions'].values() for i in region}
        self.assertEqual(ins[0x87bd95]['bytes'],'e8ca040000')
        self.assertEqual(ins[0x87bd9a]['operands'],'0x87bb3d')
        self.assertEqual(ins[0x87bbb4]['operands'],'0x87c232')
        self.assertEqual(ins[0x87bbbd]['bytes'],'7417') # C walker success branch, not unconditional traversal.
        self.assertEqual(ins[0x87bbdd]['bytes'],'751b') # Constructor walk requires initializing state.
        self.assertEqual(ins[0x87bbe9]['operands'],'0x87c22c')
        c=order['cInitializers'];cpp=order['cppInitializers']
        self.assertEqual(c['entries'][1],dict(cell=0xb63dc8,value=0x87bcb3))
        self.assertEqual(cpp['entryCount'],2468)
        self.assertIn(dict(cell=0xb6370c,value=0xb57dc0),cpp['entries'])
        self.assertFalse(c['traversalExecuted']);self.assertFalse(cpp['traversalExecuted'])

    def test_sentinel_writes_require_prior_provider_and_encoder(self):
        sentinel=self.order['cleanupSentinel']
        self.assertEqual(sentinel['argument'],0xffffffff)
        self.assertEqual(sentinel['priorProviderCall'],0x87bd1a)
        self.assertEqual(sentinel['providerCell'],0xb6138c)
        self.assertEqual([w['address'] for w in sentinel['writes']],[0x18b1e68,0x18b1e6c])
        self.assertIsNone(sentinel['encodedValue']);self.assertFalse(sentinel['runtimeExecuted'])
        self.assertEqual(self.order['cleanupGlobalRuntimeWrites'],[])
        self.assertFalse(self.order['cookieInitializerExecuted'])

    def test_frontend_manager_has_no_proven_constructor_table_link(self):
        f=self.order['frontend']
        self.assertEqual(f['initializerTableMatches'],[])
        self.assertFalse(f['incomingCallerVerified'])
        self.assertEqual(f['allocationTarget'],0x686000)
        self.assertEqual(f['publication'],0x810976)

    def test_wrong_executable_is_rejected_and_source_is_unchanged(self):
        with tempfile.TemporaryDirectory() as temp:
            wrong=Path(temp)/'wrong.exe';wrong.write_bytes(b'invalid')
            with self.assertRaisesRegex(ValueError,'SHA mismatch'):crt.inspect(wrong,self.research)
        self.assertEqual(hashlib.sha256(self.image.read_bytes()).hexdigest(),crt.SOURCE_SHA)

if __name__=='__main__':unittest.main()
