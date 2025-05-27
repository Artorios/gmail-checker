rule Test {
    meta:
        Author = "Otus"
        Description = "Test rools"
    strings:
		$signature = {
			11223344
		}

        $pass = "password"
    condition:
        $signature and $pass
}