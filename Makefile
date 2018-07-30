default:
	@echo "Type 'make install' to install pyshaper"

install:
	python setup.py install
	@echo ""
	@echo "-----------------------------------------------------"
	@echo "Seems that pyshaper might have installed successfully"
	@echo ""
	@echo "Type 'man pyshaper' for usage and configuration info"
	@echo
