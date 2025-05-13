package ipgeo

import (
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	asnDBFile  = "test-data/GeoLite2-ASN-Test.mmdb"
	cityDBFile = "test-data/GeoLite2-City-Test.mmdb"
)

func TestGetIPGeo(t *testing.T) {
	db, err := NewMMIPGeo(cityDBFile, asnDBFile)
	require.NoError(t, err)

	want := &IPGeo{
		IP:                           "81.2.69.160",
		City:                         "London",
		Subdivision:                  "England",
		Country:                      "United Kingdom",
		Proxy:                        false,
		Anycast:                      false,
		Satellite:                    false,
		AutonomousSystemOrganization: "",
	}
	got := db.GetIPGeo("81.2.69.160")
	assert.Equal(t, want, got)
}

func TestIsFileUpdated(t *testing.T) {
	tempDir := t.TempDir()

	currentFile := tempDir + "/current.txt"
	latestFile := tempDir + "/latest.txt"

	// Create dummy files
	err := os.WriteFile(currentFile, []byte("current"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(latestFile, []byte("latest"), 0644)
	require.NoError(t, err)

	// Case 1: Files are different sizes
	t.Run("different sizes", func(t *testing.T) {
		updated, _, err := isFileUpdated(currentFile, latestFile)
		require.NoError(t, err)
		assert.True(t, updated)
	})

	// Case 2: Files are same size, different content, different mod time
	t.Run("same size, different content, different mod time", func(t *testing.T) {
		err = os.WriteFile(latestFile, []byte("curren"), 0644)
		require.NoError(t, err)

		updated, _, err := isFileUpdated(currentFile, latestFile)
		require.NoError(t, err)
		assert.True(t, updated)
	})

	// Case 3: Files are same size, same content, different mod time
	t.Run("same size, same content, different mod time", func(t *testing.T) {
		err = os.WriteFile(latestFile, []byte("current"), 0644)
		require.NoError(t, err)

		updated, _, err := isFileUpdated(currentFile, latestFile)
		require.NoError(t, err)
		assert.True(t, updated)
	})

	// Case 4: Files are same size, same content, same mod time
	t.Run("same size, same content, same mod time", func(t *testing.T) {
		currentTime := time.Now()
		err = os.Chtimes(currentFile, currentTime, currentTime)
		require.NoError(t, err)
		err = os.Chtimes(latestFile, currentTime, currentTime)
		require.NoError(t, err)

		updated, _, err := isFileUpdated(currentFile, latestFile)
		require.NoError(t, err)
		assert.False(t, updated)
	})
}

func TestCopy(t *testing.T) {
	tempDir := t.TempDir()

	srcFile := tempDir + "/src.txt"
	dstFile := tempDir + "/dst.txt"

	// Create dummy file
	content := []byte("test content")
	err := os.WriteFile(srcFile, content, 0644)
	require.NoError(t, err)

	srcStat, err := os.Stat(srcFile)
	require.NoError(t, err)

	// Copy file
	err = copy(srcFile, dstFile, srcStat)
	require.NoError(t, err)

	// Check if the file is copied correctly
	dstContent, err := os.ReadFile(dstFile)
	require.NoError(t, err)
	assert.Equal(t, content, dstContent)

	dstStat, err := os.Stat(dstFile)
	require.NoError(t, err)

	assert.Equal(t, srcStat.ModTime(), dstStat.ModTime())
}

func TestAutoUpdateMMIPGeo_update(t *testing.T) {
	tempDir := t.TempDir()

	currentCityDB := tempDir + "/GeoLite2-City-Test.mmdb"
	updatedCityDB := tempDir + "/GeoLite2-City-Test.updated.mmdb"
	currentASNDB := tempDir + "/GeoLite2-ASN-Test.mmdb"
	updatedASNDB := tempDir + "/GeoLite2-ASN-Test.updated.mmdb"

	// Copy test data to temporary files
	copyFile := func(src, dst string) {
		srcFile, err := os.Open(src)
		require.NoError(t, err)
		defer srcFile.Close()

		dstFile, err := os.Create(dst)
		require.NoError(t, err)
		defer dstFile.Close()

		_, err = io.Copy(dstFile, srcFile)
		require.NoError(t, err)
	}

	copyFile(cityDBFile, currentCityDB)
	copyFile(cityDBFile, updatedCityDB) // Initially make them the same
	copyFile(asnDBFile, currentASNDB)
	copyFile(asnDBFile, updatedASNDB) // Initially make them the same

	t.Run("no update needed", func(t *testing.T) {
		db, err := NewAutoUpdateMMIPGeo(currentCityDB, updatedCityDB, currentASNDB, updatedASNDB)
		require.NoError(t, err)
		defer db.mm.Close()

		initialMM := db.mm

		// Ensure enough time has passed for the check interval
		db.lastCheck = time.Now().Add(-checkUpdateInterval - time.Minute)

		db.update()

		// Assert that the underlying MMIPGeo struct has not changed
		assert.Same(t, initialMM, db.mm)

		got := db.GetIPGeo("81.2.69.160")
		assert.Equal(t, "London", got.City)
	})

	t.Run("city db updated", func(t *testing.T) {
		db, err := NewAutoUpdateMMIPGeo(currentCityDB, updatedCityDB, currentASNDB, updatedASNDB)
		require.NoError(t, err)

		initialMM := db.mm

		// Change modify time of updated city DB to simulate update
		err = os.Chtimes(updatedCityDB, time.Now(), time.Now())
		require.NoError(t, err)

		db.lastCheck = time.Now().Add(-checkUpdateInterval - time.Minute)
		db.update()

		// Assert that the underlying MMIPGeo struct has changed
		assert.NotSame(t, initialMM, db.mm)

		got := db.GetIPGeo("81.2.69.160")
		assert.Equal(t, "London", got.City)
	})

	t.Run("asn db updated", func(t *testing.T) {
		db, err := NewAutoUpdateMMIPGeo(currentCityDB, updatedCityDB, currentASNDB, updatedASNDB)
		require.NoError(t, err)

		initialMM := db.mm

		// Change modify time of updated asn DB to simulate update
		err = os.Chtimes(updatedASNDB, time.Now(), time.Now())
		require.NoError(t, err)

		db.lastCheck = time.Now().Add(-checkUpdateInterval - time.Minute)
		db.update()

		// Assert that the underlying MMIPGeo struct has changed
		assert.NotSame(t, initialMM, db.mm)

		got := db.GetIPGeo("81.2.69.160")
		assert.Equal(t, "London", got.City)
	})

	t.Run("both dbs updated", func(t *testing.T) {
		db, err := NewAutoUpdateMMIPGeo(currentCityDB, updatedCityDB, currentASNDB, updatedASNDB)
		require.NoError(t, err)

		initialMM := db.mm

		// Modify modify time of both updated DBs to simulate update
		err = os.Chtimes(updatedCityDB, time.Now(), time.Now())
		require.NoError(t, err)
		err = os.Chtimes(updatedASNDB, time.Now(), time.Now())
		require.NoError(t, err)

		db.lastCheck = time.Now().Add(-checkUpdateInterval - time.Minute)
		db.update()

		// Assert that the underlying MMIPGeo struct has changed
		assert.NotSame(t, initialMM, db.mm)

		got := db.GetIPGeo("81.2.69.160")
		assert.Equal(t, "London", got.City)
	})
}
