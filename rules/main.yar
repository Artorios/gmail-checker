rule Example {
    meta:
        Author = "Otus"
        Description = "Test rool"
    strings:
		$signature = {
            112233445566
		}

        $str = "malware"
    condition:
        $signature and $str
}
