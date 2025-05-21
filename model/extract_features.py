# extract_features.py

import pefile
import math
import numpy as np
import os # <--- IMPORT OS MODULE HERE

# --- Constants for PE Feature Extraction (Example) ---
COMMON_SECTION_NAMES = [b'.text', b'.data', b'.rdata', b'.bss', b'.idata', b'.edata', b'.rsrc', b'.reloc', b'.tls']

def calculate_entropy(data):
    """Calculates the entropy of a byte string."""
    if not data or len(data) == 0:
        return 0.0
    entropy = 0.0
    for x_val in range(256):
        p_x = float(data.count(bytes([x_val]))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return float(entropy)

def extract_static_features(file_path, expected_feature_list):
    """
    Extracts static features from an EXE file using pefile.
    Tries to map to expected_feature_list, defaulting unmappable features to 0.0.

    Args:
        file_path (str): Path to the EXE file.
        expected_feature_list (list): List of feature names the model expects.

    Returns:
        dict: A dictionary of features (all float values), or None if basic PE parsing fails.
    """
    features = {col_name: 0.0 for col_name in expected_feature_list}
    pe = None # Initialize pe object to None

    try:
        pe = pefile.PE(file_path, fast_load=True)

        # --- Static Feature Extraction Examples ---
        if 'header.machine' in features: features['header.machine'] = float(pe.FILE_HEADER.Machine)
        if 'header.numberofsections' in features: features['header.numberofsections'] = float(pe.FILE_HEADER.NumberOfSections)
        if 'header.timedatestamp' in features: features['header.timedatestamp'] = float(pe.FILE_HEADER.TimeDateStamp)
        if 'header.pointertosymboltable' in features: features['header.pointertosymboltable'] = float(pe.FILE_HEADER.PointerToSymbolTable)
        if 'header.numberofsymbols' in features: features['header.numberofsymbols'] = float(pe.FILE_HEADER.NumberOfSymbols)
        if 'header.sizeofoptionalheader' in features: features['header.sizeofoptionalheader'] = float(pe.FILE_HEADER.SizeOfOptionalHeader)
        if 'header.characteristics' in features: features['header.characteristics'] = float(pe.FILE_HEADER.Characteristics)

        if hasattr(pe, 'OPTIONAL_HEADER'):
            if 'optional.magic' in features: features['optional.magic'] = float(pe.OPTIONAL_HEADER.Magic)
            if 'optional.addressofentrypoint' in features: features['optional.addressofentrypoint'] = float(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            if 'optional.imagebase' in features: features['optional.imagebase'] = float(pe.OPTIONAL_HEADER.ImageBase)
            if 'optional.sectionalignment' in features: features['optional.sectionalignment'] = float(pe.OPTIONAL_HEADER.SectionAlignment)
            if 'optional.filealignment' in features: features['optional.filealignment'] = float(pe.OPTIONAL_HEADER.FileAlignment)
            if 'optional.majoroperatingsystemversion' in features: features['optional.majoroperatingsystemversion'] = float(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)
            if 'optional.minoroperatingsystemversion' in features: features['optional.minoroperatingsystemversion'] = float(pe.OPTIONAL_HEADER.MinorOperatingSystemVersion)
            if 'optional.sizeofimage' in features: features['optional.sizeofimage'] = float(pe.OPTIONAL_HEADER.SizeOfImage)
            if 'optional.sizeofheaders' in features: features['optional.sizeofheaders'] = float(pe.OPTIONAL_HEADER.SizeOfHeaders)
            if 'optional.checksum' in features: features['optional.checksum'] = float(pe.OPTIONAL_HEADER.CheckSum)
            if 'optional.subsystem' in features: features['optional.subsystem'] = float(pe.OPTIONAL_HEADER.Subsystem)
            if 'optional.dllcharacteristics' in features: features['optional.dllcharacteristics'] = float(pe.OPTIONAL_HEADER.DllCharacteristics)
            if 'optional.numberofrvaandsizes' in features: features['optional.numberofrvaandsizes'] = float(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes)
        
        features['section.nsections'] = float(pe.FILE_HEADER.NumberOfSections)
        section_entropies = []
        section_virtual_sizes = []
        section_raw_sizes = []
        executable_sections = 0
        for section in pe.sections:
            s_data = section.get_data()
            section_entropies.append(calculate_entropy(s_data))
            section_virtual_sizes.append(float(section.Misc_VirtualSize))
            section_raw_sizes.append(float(section.SizeOfRawData))
            if section.IMAGE_SCN_MEM_EXECUTE:
                executable_sections += 1
                if 'section.executable_entropy' in features and features['section.executable_entropy'] == 0.0:
                     features['section.executable_entropy'] = calculate_entropy(s_data)

        if 'section.avg_entropy' in features: features['section.avg_entropy'] = float(np.mean(section_entropies) if section_entropies else 0.0)
        if 'section.max_entropy' in features: features['section.max_entropy'] = float(np.max(section_entropies) if section_entropies else 0.0)
        if 'section.min_entropy' in features: features['section.min_entropy'] = float(np.min(section_entropies) if section_entropies else 0.0)
        if 'section.avg_virtualsize' in features: features['section.avg_virtualsize'] = float(np.mean(section_virtual_sizes) if section_virtual_sizes else 0.0)
        if 'section.avg_rawsize' in features: features['section.avg_rawsize'] = float(np.mean(section_raw_sizes) if section_raw_sizes else 0.0)
        if 'section.nexecutable' in features: features['section.nexecutable'] = float(executable_sections)

        num_imported_dlls = 0
        num_imported_functions = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            num_imported_dlls = len(pe.DIRECTORY_ENTRY_IMPORT)
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                num_imported_functions += len(entry.imports)
        if 'imports.ndlls' in features: features['imports.ndlls'] = float(num_imported_dlls)
        if 'imports.nfuncs' in features: features['imports.nfuncs'] = float(num_imported_functions)
        
        if 'pslist.nproc' in features: features['pslist.nproc'] = float(pe.FILE_HEADER.NumberOfSections) 
        if 'handles.nfile' in features: features['handles.nfile'] = float(sum(s.SizeOfRawData for s in pe.sections))
        if 'callbacks.ncallbacks' in features: features['callbacks.ncallbacks'] = float(num_imported_dlls)
        if 'dlllist.ndlls' in features: features['dlllist.ndlls'] = float(num_imported_dlls)

        for key in features:
            if not isinstance(features[key], float):
                try:
                    features[key] = float(features[key])
                except ValueError:
                    print(f"[WARNING] Could not convert feature {key} value '{features[key]}' to float. Setting to 0.0.")
                    features[key] = 0.0
        
        # Use os.path.basename here
        print(f"Static features extracted for {os.path.basename(file_path)}: {len(features)} features.")
        return features

    except pefile.PEFormatError as e:
        print(f"[ERROR] PEFormatError for {file_path}: {e}. File might not be a valid PE or is corrupted.")
        return None # Return None if PE parsing fails fundamentally
    except Exception as e:
        print(f"[ERROR] Feature extraction failed for {file_path}: {e}")
        return None # Return None on other errors too
    finally:
        if pe:
            pe.close() # <--- EXPLICITLY CLOSE THE PE FILE
            print(f"PE file {file_path} closed.")
