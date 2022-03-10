from .emu import ELFPCodeEmu, PCodeEmu


class PCodeEmuHeadlessMixin:
    def run_headless(self):
        import ghidra_bridge

        with ghidra_bridge.GhidraBridge(namespace=globals()) as b:
            EmulatorHelper = b.remote_import("ghidra.app.emulator").EmulatorHelper
            SymbolUtilities = b.remote_import(
                "ghidra.program.model.symbol"
            ).SymbolUtilities

            def getAddress(offset):
                return (
                    currentProgram.getAddressFactory()
                    .getDefaultAddressSpace()
                    .getAddress(offset)
                )

            def getSymbolAddress(symbolName):
                symbol = SymbolUtilities.getLabelOrFunctionSymbol(
                    currentProgram, symbolName, None
                )
                if symbol != None:
                    return symbol.getAddress()
                else:
                    raise ("Failed to locate label: {}".format(symbolName))

            def getProgramRegisterList(currentProgram):
                pc = currentProgram.getProgramContext()
                return pc.registers

            CONTROLLED_RETURN_OFFSET = self.ret_addr

            # Identify function to be emulated
            mainFunctionEntry = getSymbolAddress("main")

            # Establish emulation helper, please check out the API docs
            # for `EmulatorHelper` - there's a lot of helpful things
            # to help make architecture agnostic emulator tools.
            emuHelper = EmulatorHelper(currentProgram)

            # Set controlled return location so we can identify return from emulated function
            controlledReturnAddr = getAddress(CONTROLLED_RETURN_OFFSET)

            # Set initial RIP
            emuHelper.writeRegister(emuHelper.getPCRegister(), self.entry)

            # For x86_64 `registers` contains 872 registers! You probably don't
            # want to print all of these. Just be aware, and print what you need.
            # To see all supported registers. just print `registers`.
            # We won't use this, it's just here to show you how to query
            # valid registers for your target architecture.
            registers = getProgramRegisterList(currentProgram)
            print("getContextRegister: %s" % str(emuHelper.getContextRegister()))

            # Here's a list of all the registers we want printed after each
            # instruction. Modify this as you see fit, based on your architecture.
            reg_filter = []

            # Setup your desired starting state. By default, all registers
            # and memory will be 0. This may or may not be acceptable for
            # you. So please be aware.
            emuHelper.writeRegister("r5", 5)
            emuHelper.writeRegister("r1", self.initial_sp)
            emuHelper.writeRegister("r15", self.ret_addr - 8)

            print("Emulation starting at 0x{}".format(self.entry))
            while monitor.isCancelled() == False:

                # Check the current address in the program counter, if it's
                # zero (our `CONTROLLED_RETURN_OFFSET` value) stop emulation.
                # Set this to whatever end target you want.
                executionAddress = emuHelper.getExecutionAddress()
                if executionAddress == controlledReturnAddr:
                    print("Emulation complete.")
                    r3 = emuHelper.readRegister("r3")
                    print("r3 after headless emu: {:#010x}".format(r3))
                    return

                # Print current instruction and the registers we care about
                print(
                    "Address: 0x{} ({})".format(
                        executionAddress, getInstructionAt(executionAddress)
                    )
                )
                for reg in reg_filter:
                    reg_value = emuHelper.readRegister(reg)
                    print("  {} = {:#018x}".format(reg, reg_value))

                # single step emulation
                success = emuHelper.step(monitor)
                if success == False:
                    lastError = emuHelper.getLastError()
                    printerr("Emulation Error: '{}'".format(lastError))
                    return

            # Cleanup resources and release hold on currentProgram
            emuHelper.dispose()


class PCodeEmuHeadless(PCodeEmu, PCodeEmuHeadlessMixin):
    pass


class ELFPCodeEmuHeadless(ELFPCodeEmu, PCodeEmuHeadlessMixin):
    pass
