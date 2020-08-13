PLUGIN_VERSION=1.0.1
PLUGIN_ID=azure-ad-sync

plugin:
	cat plugin.json|json_pp > /dev/null
	rm -rf dist
	mkdir dist
	zip --exclude "*.pyc" -r dist/dss-plugin-${PLUGIN_ID}-${PLUGIN_VERSION}.zip parameter-sets python-lib plugin.json code-env python-runnables
