package packages

func platformSources() []Source {
	return []Source{
		appBundleSource(appDirs, readInfoPlist),
		brewSource(brewPrefixes),
		pkgutilSource(runCommand),
	}
}
