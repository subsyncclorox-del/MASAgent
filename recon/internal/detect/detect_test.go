package detect

import "testing"

func TestLooksRealRejectsHTMLShell(t *testing.T) {
	shop := "<html><head><title>Shop</title></head><body><p>results for phpinfo.php</p></body></html>"
	if looksReal("/phpinfo.php", shop) {
		t.Error("reflected 'phpinfo.php' inside an HTML page must not count as a real phpinfo")
	}
	if looksReal("/.env", shop) {
		t.Error("an HTML page must not count as an exposed .env")
	}
	if looksReal("/.svn/entries", shop) {
		t.Error("an HTML page must not count as exposed .svn")
	}
}

func TestLooksRealAcceptsRealContent(t *testing.T) {
	if !looksReal("/.env", "SECRET_KEY=abc\nDB_PASSWORD=hunter2\n") {
		t.Error("a real .env body should be detected")
	}
	if !looksReal("/.git/config", "[core]\n\trepositoryformatversion = 0\n") {
		t.Error("a real .git/config should be detected")
	}
	if !looksReal("/phpinfo.php", "<title>phpinfo()</title> PHP Version 8.1 System Linux") {
		t.Error("a real phpinfo page should be detected")
	}
}

func TestOrigin(t *testing.T) {
	got, err := origin("http://127.0.0.1:8081/search?q=1/phpinfo.php")
	if err != nil {
		t.Fatal(err)
	}
	if got != "http://127.0.0.1:8081" {
		t.Errorf("origin = %q, want scheme+host only", got)
	}
}
