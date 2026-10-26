package packages

func platformSources() []Source {
	return []Source{
		dpkgSource(dpkgStatusPath),
		apkSource(apkInstalledPath),
		rpmSource("rpm", runCommand),
	}
}
