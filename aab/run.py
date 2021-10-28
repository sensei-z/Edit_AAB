# coding=utf-8
import datetime
import json
import re
import yaml
import argparse
import time
import sys
import xml.etree.ElementTree as ET

if hasattr(sys, "_flask"):
    from .utils import *
else:
    try:
        from utils import *
    except:
        from .utils import *


def print_log(message):
    if global_print_fun:
        global_print_fun(message)
    else:
        print(message)
    pass


def get_base_dir() -> str:
    if hasattr(sys, "_flask"):
        return os.path.dirname(os.path.realpath(__file__))
    if hasattr(sys, "_MEIPASS"):
        return sys._MEIPASS
    return ""


APKTOOL_PATH = os.path.join(get_base_dir(), "libs", "apktool-2.5.2-fixed.jar")
AAPT2_PATH = os.path.join(get_base_dir(), "libs", "aapt2", get_system(), "aapt2")
ANDROID_JAR_PATH = os.path.join(get_base_dir(), "libs", "android_sdk.jar")
BUNDLETOOL_TOOL_PATH = os.path.join(get_base_dir(), "libs", "bundletool-all-1.8_fix.jar")

KEYSTORE = os.path.join(get_base_dir(), "libs", "android.keystore")
STORE_PASSWORD = "android" # if your keystore password is different then kindly replace the "android" with your password
KEY_ALIAS = "androidkey"  # if your keystore password is different then kindly replace the "androidkey" with your password
KEY_PASSWORD = "android"  # if your keystore password is different then kindly replace the "android" with your password

BUNDLE_MODULE_TEMPLATE_PATH = os.path.join(get_base_dir(), "libs", "template_data")


def task(task_name, fun, *args, **kwargs):
    print_log(f"---{task_name}")
    start_time = time.time()
    status, msg = fun(*args, **kwargs)
    end_time = time.time()
    print_log(f"---time consuming:{end_time - start_time} {task_name} status:{status} msg:{msg}")
    if status != 0:
        raise Exception(f"task {task_name} Execution abnormal status:{status} msg:{msg}")


def compile_resources(compile_source_res_dir: str, compiled_resources: str, aapt2: str):
    
    cmd = f"{aapt2} compile --legacy\
        --dir {compile_source_res_dir} \
        -o {compiled_resources} "
    return execute_cmd(cmd)


def link_resources(link_out_apk_path: str,
                   input_manifest: str,
                   android: str,
                   min_sdk_version: str,
                   target_sdk_version: str,
                   version_code: str,
                   version_name: str,
                   aapt2: str,
                   compiled_resources_path: str = None,
                   public_id_path: str = None):

    cmd = f"{aapt2} link --proto-format \
        -o {link_out_apk_path} \
        -I {android} \
        --min-sdk-version {min_sdk_version} \
        --target-sdk-version {target_sdk_version}\
        --version-code {version_code}\
        --version-name {version_name}\
        --manifest {input_manifest} \
        --auto-add-overlay"

    if compiled_resources_path and os.path.exists(compiled_resources_path):
        cmd += f" -R {compiled_resources_path}"
    if public_id_path and os.path.exists(public_id_path):
        cmd += f" --stable-ids {public_id_path}"
    return execute_cmd(cmd)


def delete_sign(meta_inf_path):
    
    meta_inf_list = os.listdir(meta_inf_path)
    for i in meta_inf_list:
        if not i.endswith(".RSA") or not i.endswith(".SF") or not i.endswith(".MF"):
            continue
        delete(os.path.abspath(i))
    return 0, "success"


def copy_dex(base_dir_path, target_dex_path):
  

    dex_array = list(filter(lambda x: x.endswith("dex"), os.listdir(base_dir_path)))
    dex_path_array = list(
        map(lambda x: os.path.join(base_dir_path, x), dex_array))
    for dex in dex_path_array:
        basename = os.path.basename(dex)
        status, msg = copy(dex, os.path.join(target_dex_path, basename))
        if status != 0:
            return status, msg
    return 0, "success"


def build_bundle(bundletool: str, modules: str, out_aab_path: str, bundle_config_json_path: str = None):
   
    cmd = f"java -jar {bundletool} build-bundle \
        --modules={modules} \
        --output={out_aab_path} "
    if bundle_config_json_path and os.path.exists(bundle_config_json_path):
        cmd += f" --config={bundle_config_json_path}"
    return execute_cmd(cmd)


def decode_apk(apk_path: str, decode_apk_dir: str, apktool: str = None):
    cmd = f"java -jar {apktool} d {apk_path} -s -o {decode_apk_dir}"
    return execute_cmd(cmd)


def pad_mv_assets(base_dir, pad_dir, pad_reg):
    
    base_dir = os.path.join(base_dir, "assets")
    pad_dir = os.path.join(pad_dir, "assets")
    file_name_list = get_file_name_list(base_dir)
    pattern = re.compile(pad_reg)
 
    mv_file_name = []
    for file_name in file_name_list:
        temp_file_name = file_name[1:] if file_name[0] == "/" or file_name[0] == "\\" else file_name
        if pattern.match(temp_file_name):
    
            mv_file_name.append(temp_file_name)
    for temp in mv_file_name:
        mv(os.path.join(base_dir, temp),
           os.path.join(pad_dir, temp))
    return 0, "success"


def create_pad_module_dir(temp_dir, module_name, package):
   
    status, message = copy(BUNDLE_MODULE_TEMPLATE_PATH, temp_dir)
    if status != 0:
        return status, message
    template_android_manifest_path = os.path.join(temp_dir, "AndroidManifest.xml")
    text = read_file_text(template_android_manifest_path).replace("$padName", module_name).replace("$applicationId",
                                                                                                   package)
    write_file_text(template_android_manifest_path, text)
    return 0, "success"


def sign(temp_aab_path, keystore, storepass, keypass, alias):
    cmd = f"jarsigner -digestalg SHA1 -sigalg SHA1withRSA \
        -keystore {keystore} \
        -storepass {storepass} \
        -keypass {keypass} \
        {temp_aab_path} \
        {alias}"
    return execute_cmd(cmd)


def create_bundle_config_json(bundle_config_json_path: str, do_not_compress: list):
    glob_not_compress = ['**.3[gG]2', '**.3[gG][pP]', '**.3[gG][pP][pP]', '**.3[gG][pP][pP]2', '**.[aA][aA][cC]',
                         '**.[aA][mM][rR]', '**.[aA][wW][bB]', '**.[gG][iI][fF]', '**.[iI][mM][yY]', '**.[jJ][eE][tT]',
                         '**.[jJ][pP][eE][gG]', '**.[jJ][pP][gG]', '**.[mM]4[aA]', '**.[mM]4[vV]', '**.[mM][iI][dD]',
                         '**.[mM][iI][dD][iI]', '**.[mM][kK][vV]', '**.[mM][pP]2', '**.[mM][pP]3', '**.[mM][pP]4',
                         '**.[mM][pP][eE][gG]', '**.[mM][pP][gG]', '**.[oO][gG][gG]', '**.[oO][pP][uU][sS]',
                         '**.[pP][nN][gG]', '**.[rR][tT][tT][tT][lL]', '**.[sS][mM][fF]', '**.[tT][fF][lL][iI][tT][eE]',
                         '**.[wW][aA][vV]', '**.[wW][eE][bB][mM]', '**.[wW][eE][bB][pP]', '**.[wW][mM][aA]',
                         '**.[wW][mM][vV]', '**.[xX][mM][fF]']
    do_not_compress = list(filter(lambda x: not x.startswith("META-INF"), do_not_compress))
    do_not_compress += glob_not_compress
    config = {"bundletool": {"version": "1.2.3"}, "compression": {"uncompressedGlob": do_not_compress}, }
    data = json.dumps(config)
    write_file_text(bundle_config_json_path, data)
    return 0, "success"


class Bundletool:

    def __init__(self, keystore=KEYSTORE,
                 storepass=STORE_PASSWORD,
                 alias=KEY_ALIAS,
                 keypass=KEY_PASSWORD,
                 apktool=APKTOOL_PATH,
                 aapt2=AAPT2_PATH,
                 android=ANDROID_JAR_PATH,
                 bundletool=BUNDLETOOL_TOOL_PATH,
                 print_fun=None):
        global global_print_fun
        global_print_fun = print_fun
        self.pad_reg = ""
        self.keystore = os.path.abspath(keystore)
        self.storepass = storepass
        self.alias = alias
        self.keypass = keypass
        self.apktool = os.path.abspath(apktool)
        self.aapt2 = os.path.abspath(aapt2)
        self.android = os.path.abspath(android)
        self.bundletool = os.path.abspath(bundletool)


        self.min_sdk_version = 19
        self.target_sdk_version = 30
        self.version_code = 1 # replace this with your version
        self.version_name = "1.0.0" # replace this with your version
        self.apk_package_name = ""

        self.do_not_compress = []

  
        self.bundle_modules = {}

    def check_system(self, apk_path, out_aab_path):
        print_log(f"[Current system]:{get_system()}")
        print_log(f"[Current system JAVA version]*****:")
        _, msg = execute_cmd("java -version")
        print_log(f"[Enter apk]:{apk_path}")
        if not os.path.exists(apk_path):
            return -1, f"The entered apk does not exist:{apk_path}"
        print_log(f"[Output aab]:{out_aab_path}")
        print_log(f"[sign]:{self.keystore},storepass:{self.storepass},alias:{self.alias},keypass:{self.keypass}")
        if not os.path.exists(self.keystore):
            return -2, f"The entered keystore does not exist:{self.keystore}"
        status, msg = execute_cmd(
            f"keytool -list -v -keystore {self.keystore} -storepass {self.storepass} -alias {self.alias} ")
        status += status
        print_log(f"######################################################")
        if get_system() in [MACOS, Linux]:
            status, msg = execute_cmd(
                f"keytool -exportcert -alias {self.alias} -keystore {self.keystore} -storepass {self.storepass} | openssl sha1 -binary | openssl base64")
            if status != 0:
                return -999, "Signature error"
        else:
            print_log("Window")
        print_log(f"######################################################")
        print_log(f"[apktool]:{self.apktool}")
        print_log(f"[apktool version number]:------")
        status, msg = execute_cmd(f"java -jar {self.apktool} --version")
        status += status
       
        if get_system() in [MACOS, Linux]:
            try:
                execute_cmd(f"chmod +x {self.aapt2}")
            except Exception as e:
                print_log("Authorization failed:", e)
                pass
            pass
        print_log(f"[aapt2]:{self.aapt2}")
        print_log(f"[aapt2 version number]:------")
        status, msg = execute_cmd(f"{self.aapt2} version")
        status += status
        print_log(f"[android]:{self.android}")
        if not os.path.exists(self.android):
            return -3, f"The entered android.jar does not exist:f{self.android}"
        print_log(f"[bundletool]:{self.bundletool}")
        print_log(f"[bundletool version number]:------")
        status, msg = execute_cmd(f"java -jar {self.bundletool} version")
        status += status
        return status, "success"

    def build_public_id(self, public_path, decode_apk_dir):
        apk_public_path = os.path.join(decode_apk_dir, "res", "values", "public.xml")
        tree = ET.parse(apk_public_path)
        root = tree.getroot()
        s = []
        for i in root:
            x_type = i.attrib["type"]
            x_name = i.attrib["name"]
            x_id = i.attrib["id"]
            s.append(f"{self.apk_package_name}:{x_type}/{x_name} = {x_id}\n")
        write_file_text(public_path, "".join(s))
        return 0, "success"

    def analysis_apk(self, decode_apk_dir):
        content = read_file_text(os.path.join(decode_apk_dir, "apktool.yml"))
        content = content.replace("!!brut.androlib.meta.MetaInfo", "")
        data = yaml.load(content, Loader=yaml.FullLoader)
        sdk_info = data["sdkInfo"]
        self.min_sdk_version = sdk_info["minSdkVersion"]
        self.target_sdk_version = sdk_info["targetSdkVersion"]

        version_info = data["versionInfo"]
        self.version_code = version_info["versionCode"]
        self.version_name = version_info["versionName"]

        self.do_not_compress = data["doNotCompress"]

        tree = ET.parse(os.path.join(decode_apk_dir, "AndroidManifest.xml"))
        root = tree.getroot()
        package = root.attrib["package"]
        self.apk_package_name = package
        return 0, "success"

    def is_pad(self):
        return len(self.pad_reg) > 0

    def build_module_zip(self, temp_dir: str, module_name: str, input_resources_dir: str, out_module_zip_path: str,
                         public_id_path: str = None):
        
        module_dir_temp = os.path.join(temp_dir, module_name + "_temp")
        os.makedirs(module_dir_temp)

        input_res_dir = os.path.join(input_resources_dir, "res")

        input_manifest = os.path.join(input_resources_dir, "AndroidManifest.xml")

        input_assets = os.path.join(input_resources_dir, "assets")

        input_lib = os.path.join(input_resources_dir, "lib")

        input_unknown = os.path.join(input_resources_dir, "unknown")

        input_kotlin = os.path.join(input_resources_dir, "kotlin")

        input_meta_inf_path = os.path.join(input_resources_dir, "original", "META-INF")

        compiled_resources = os.path.join(module_dir_temp, "compiled_resources.zip")

        link_base_apk_path = os.path.join(module_dir_temp, "base.apk")

        unzip_link_apk_path = os.path.join(module_dir_temp, module_name)


        temp_android_manifest_path = os.path.join(unzip_link_apk_path, "AndroidManifest.xml")

        target_android_manifest_path = os.path.join(unzip_link_apk_path, "manifest", "AndroidManifest.xml")

        target_assets_path = os.path.join(unzip_link_apk_path, "assets")

        target_lib_path = os.path.join(unzip_link_apk_path, "lib")

        target_unknown_path = os.path.join(unzip_link_apk_path, "root")

        target_kotlin_path = os.path.join(target_unknown_path, "kotlin")

        target_mata_inf_path = os.path.join(target_unknown_path, "META-INF")

        target_dex_path = os.path.join(unzip_link_apk_path, "dex")


        if os.path.exists(input_res_dir):
            try:
                
                task(f"[{module_name}]-Compile resources", compile_resources, input_res_dir, compiled_resources, self.aapt2)
            except Exception as e:
                print_log(f"[{module_name}]-Compile resource error {str(e)}")
                pass
        task(f"[{module_name}]-Associated resources", link_resources, link_base_apk_path, input_manifest, self.android,
             self.min_sdk_version,
             self.target_sdk_version, self.version_code, self.version_name, self.aapt2, compiled_resources,
             public_id_path=public_id_path)

        task(f"[{module_name}]-Unzip the resources apk", unzip_file, link_base_apk_path, unzip_link_apk_path)

        task(f"[{module_name}]-Data_AndroidManifest", mv, temp_android_manifest_path, target_android_manifest_path)

        if os.path.exists(input_assets):
            task(f"[{module_name}]-Copy assets", copy, input_assets, target_assets_path)
        if os.path.exists(input_lib):
            task(f"[{module_name}]-Copy lib", copy, input_lib, target_lib_path)

        if os.path.exists(input_unknown):
            task(f"[{module_name}]-Copy unknown", copy, input_unknown, target_unknown_path)
  
        if os.path.exists(input_kotlin):
            task(f"[{module_name}]-Copy kotlin", copy, input_kotlin, target_kotlin_path)
    
        if os.path.exists(input_meta_inf_path):
            task(f"[{module_name}]-Process the original apk signature information", delete_sign, input_meta_inf_path)
   
        if os.path.exists(input_meta_inf_path):
            task(f"[{module_name}]-Copy META-INF", copy, input_meta_inf_path, target_mata_inf_path)
   
        if os.path.exists(input_resources_dir):
            task(f"[{module_name}]-Copy dex", copy_dex, input_resources_dir, target_dex_path)
   
        task(f"[{module_name}]-Compressed zip", zip_file, unzip_link_apk_path, out_module_zip_path)
        return 0, "success"

    def run(self, apk_path, out_aab_path, pad_reg=""):
        self.pad_reg = pad_reg

      
        temp_dir = f"temp_{'{0:%Y%m%d%H%M%S}'.format(datetime.datetime.now())}"
        if os.path.exists(temp_dir):
            delete(temp_dir)
        os.mkdir(temp_dir)

        module_zip_dir = os.path.join(temp_dir, "modules")
        os.mkdir(module_zip_dir)

        decode_apk_dir = os.path.join(temp_dir, "decode_apk_dir")

        temp_aab_path = os.path.join(temp_dir, "base.aab")


        self.bundle_modules["base"] = decode_apk_dir

        public_id_path = os.path.join(temp_dir, "public.txt")

        try:
            task("Environment & parameter verification", self.check_system, apk_path, out_aab_path)
            task("Unzip input_apk", decode_apk, apk_path, decode_apk_dir, self.apktool)
            task("Parse apk information", self.analysis_apk, decode_apk_dir)
            task("Build public.txt", self.build_public_id, public_id_path, decode_apk_dir)
            if self.is_pad():
                module_name = "pad_sy"
                pad_module_temp_dir = os.path.join(temp_dir, module_name)
                package = self.apk_package_name
                task("Build a pad module", create_pad_module_dir, pad_module_temp_dir, module_name, package)
                task("Move resources to the pad module", pad_mv_assets, decode_apk_dir, pad_module_temp_dir, self.pad_reg)
                self.bundle_modules[module_name] = pad_module_temp_dir

            for name, path in self.bundle_modules.items():
                task(f"[{name}]-Build the module compression package", self.build_module_zip, temp_dir, name, path,
                     os.path.join(module_zip_dir, name + ".zip"), public_id_path)

            all_module_name = self.bundle_modules.keys()

            all_module_path = list(map(lambda x: os.path.join(module_zip_dir, x + ".zip"), all_module_name))

            modules = ",".join(all_module_path)
            bundle_config_json_path = os.path.join(temp_dir, "BundleConfig.pb.json")
            task("Construct config json", create_bundle_config_json, bundle_config_json_path, self.do_not_compress)
            task("Construct aab", build_bundle, self.bundletool, modules, temp_aab_path, bundle_config_json_path)
            task("sign", sign, temp_aab_path, self.keystore, self.storepass, self.keypass, self.alias)
            task("AAB has generated in outPut", copy, temp_aab_path, out_aab_path)
        except Exception as e:
            print_log(e)
            return -1, str(e)
        finally:
            pass
            status, _ = delete(temp_dir)
        return 0, "success"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="APK TO AAB by Simple ")
    parser.add_argument("-i", "--input", help="Enter the path of the apk", required=True)
    parser.add_argument("-o", "--output", help="Path to output apk", required=True)
    parser.add_argument("--keystore", help="Signature file path", default=KEYSTORE)
    parser.add_argument("--store_password", help="Signature file path",
                        default=STORE_PASSWORD)
    parser.add_argument("--key_alias", help="Signature file path", default=KEY_ALIAS)
    parser.add_argument("--key_password", help="Signature file path", default=KEY_PASSWORD)
    parser.add_argument("--apktool", help="apktool.jar path",
                        default=APKTOOL_PATH)
    parser.add_argument("--aapt2", help="aapt2 path", default=AAPT2_PATH)
    parser.add_argument("--android", help="android.jar path",
                        default=ANDROID_JAR_PATH)
    parser.add_argument(
        "--bundletool", help="bundletool.jar path", default=BUNDLETOOL_TOOL_PATH)
    parser.add_argument(
        "--pad_reg", help="Extract the pad resource from the Assets directory and match the file copy through regular", default="")
    args = parser.parse_args()

    input_apk_path = os.path.abspath(args.input)
    output_aab_path = os.path.abspath(args.output)
    keystore = args.keystore
    store_password = args.store_password
    key_alias = args.key_alias
    key_password = args.key_password
    input_apktool_path = args.apktool
    aapt2 = args.aapt2
    android = args.android
    bundletool = args.bundletool
    input_pad_reg = args.pad_reg

    bundletool = Bundletool(keystore=keystore,
                            storepass=store_password,
                            alias=key_alias,
                            keypass=key_password,
                            apktool=input_apktool_path,
                            aapt2=aapt2,
                            android=android,
                            bundletool=bundletool)
    status, message = bundletool.run(apk_path=input_apk_path,
                                     out_aab_path=output_aab_path,
                                     pad_reg=input_pad_reg)

    sys.exit(status)
pass
