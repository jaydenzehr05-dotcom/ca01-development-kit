from pathlib import Path
p=Path('/home/starlight/projects/rav4-radio/ca01-development-kit/tests/test_loader_sandbox.py')
s=p.read_text()
s=s.replace('def elf(kind=2, machine=40):\n    data = bytearray(64)','def elf(kind=2, machine=40, interpreter=b"/lib/ld-linux.so.3\\0"):\n    data = bytearray(128)')
s=s.replace("    struct.pack_into('<HH', data, 16, kind, machine)\n    return bytes(data)","    struct.pack_into('<HH', data, 16, kind, machine)\n    if interpreter is not None:\n        struct.pack_into('<I', data, 28, 52)\n        struct.pack_into('<HH', data, 42, 32, 1)\n        struct.pack_into('<IIIIIIII', data, 52, 3, 96, 0, 0, len(interpreter), len(interpreter), 4, 1)\n        data[96:96 + len(interpreter)] = interpreter\n    return bytes(data)")
needle='    def test_command_enforces_isolation_trace_only_and_guest_base(self):'
assert needle in s
new='''    def replace_elf(self, row, data):
        p = Path(row['local_path']); p.chmod(0o644); p.write_bytes(data)
        row.update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
        self.save([row])

    def test_static_executable_rejected_before_output(self):
        row = self.row(); self.replace_elf(row, elf(interpreter=None))
        with self.assertRaisesRegex(ValueError, 'interpreter'):
            stage_verified_elfs(self.manifest, self.output)
        self.assertFalse(self.output.exists())

    def test_custom_interpreter_rejected_before_output(self):
        row = self.row(); self.replace_elf(row, elf(interpreter=b'/opt/custom-loader\\0'))
        with self.assertRaisesRegex(ValueError, 'interpreter'):
            stage_verified_elfs(self.manifest, self.output)
        self.assertFalse(self.output.exists())

    def test_out_of_bounds_program_headers_rejected(self):
        row = self.row(); data = bytearray(elf()); struct.pack_into('<I', data, 28, 4096)
        self.replace_elf(row, bytes(data))
        with self.assertRaisesRegex(ValueError, 'program header'):
            stage_verified_elfs(self.manifest, self.output)
        self.assertFalse(self.output.exists())

    def test_approved_target_cannot_be_static_shared_object(self):
        row = self.row(); self.replace_elf(row, elf(kind=3, interpreter=None))
        with self.assertRaisesRegex(ValueError, 'interpreter'):
            stage_verified_elfs(self.manifest, self.output)
        self.assertFalse(self.output.exists())

'''
s=s.replace(needle,new+needle);p.write_text(s)
