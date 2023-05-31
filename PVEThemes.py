import os
import sys
try:
    import sass
    from sass import compile
except ImportError:
    print("FATAL: requirements missing, please run 'pip3 install -r requirements.txt'")
    exit(1)

proxmoxLibLocation = "/usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js"
pvemanagerlibLocation = "/usr/share/pve-manager/js/pvemanagerlib.js"
API2_Nodes = "/usr/share/perl5/PVE/API2/Nodes.pm"
#proxmoxLibLocation = "proxmoxlib.js"

def appendThemeMap(themeFileName, themeTitle):
    #open the proxmoxlib.js file
    f = open(proxmoxLibLocation, "r+", encoding="utf8")
    #read the file
    fileContents = f.read()

    #find the line that contains the theme_map variable
    themeMapLine = fileContents.find("theme_map: {")
    #find the end of the theme_map variable
    themeMapEnd = fileContents.find("}", themeMapLine)
    #get the theme_map variable
    themeMap = fileContents[themeMapLine:themeMapEnd]

    themeMap += "\"" + themeFileName + "\": \"" + themeTitle + "\",\n"

    #replace the theme_map variable with the new one
    fileContents = fileContents.replace(fileContents[themeMapLine:themeMapEnd], themeMap)

    #write to the file
    f.seek(0)
    f.write(fileContents)
    f.truncate()
    f.close()

def reinstallProxmoxWidgetToolkit():
    #if on linux, we should be on a proxmox machine, so apt reinstall proxmox-widget-toolkit to get the original proxmoxlib.js file
    if os.name == "posix":
        print("Reinstalling proxmox source files...")
        print("----------APT OUTPUT----------")
        os.system("apt -qq -o=Dpkg::Use-Pty=0 reinstall proxmox-widget-toolkit pve-manager")
        print("------------------------------")

def compileSassThemes():
    print("Compiling SASS themes...")
    #get all of the .sass themes to compile
    themes = os.listdir("themes")

    for theme in themes:
        #check if it is a .sass file
        if theme.find(".sass") == -1:
            continue
        
        print("Compiling " + theme + "...")
        f = open("themes/" + theme, "r", encoding="utf8")
        #compile the sass file
        compiledSASS = sass.compile(string=f.read(), output_style="compressed")
        f.close()

        #create a new .css file with the compiled sass
        f = open("themes/" + theme[:theme.find(".sass")] + ".css", "w", encoding="utf8")
        f.write(compiledSASS)
        f.close()
    print("Done compiling SASS themes...")

#patches all of the themes into the proxmoxlib.js file and copys the themes into the themes folder
def patchThemes():
    print("Patching themes...")
    #get all of the .css themes to install in the themes folder
    themes = os.listdir("themes")

    for theme in themes:
        #check if it is a .css file
        if theme.find(".css") == -1:
            continue


        #read in the first line of the theme file
        f = open("themes/" + theme, "r", encoding="utf8")
        firstLine = f.readline()

        #extract the theme name from the first line comment, which is between /* and */
        themeTitle = firstLine[firstLine.find("/*!") + 3:firstLine.find("*/")]

        #get the theme file name without the .css extension and missing the theme- prefix
        themeFileName = theme[theme.find("theme-") + 6:theme.find(".css")]

        print("Patching " + themeTitle + " into proxmoxlib.js...")
        appendThemeMap(themeFileName, themeTitle)

    if os.name == "posix":
        #copy all the themes into the themes folder
        os.system("cp themes/* /usr/share/javascript/proxmox-widget-toolkit/themes")

    print("Done patching themes into proxmoxlib.js...")

def addButton(function, buttonName):
    print("Adding button to the PVE web interface...")
    #open the proxmoxlib.js file
    f = open(proxmoxLibLocation, "r+", encoding="utf8")
    #read the file
    fileContents = f.read()


    #find the Ext.define('Proxmox.window.ThemeEditWindow', { line
    themeEditWindowLine = fileContents.find("Ext.define('Proxmox.window.ThemeEditWindow', {")
    #find the end of the Ext.define('Proxmox.window.ThemeEditWindow', { line
    themeEditWindowEnd = fileContents.find("});", themeEditWindowLine)
    #get the define
    themeEditWindow = fileContents[themeEditWindowLine:themeEditWindowEnd]

    #find the controller array
    controllerLine = themeEditWindow.find("controller: {")

    #define what our button does
    buttonFunction = """
        functionName: async function(button) {
			let view = this.getView();
			let vm = this.getViewModel();
			view.mask(gettext('Please wait...'), 'x-mask-loading');

            await sendShellCommand("cd ~/PVEThemes && python3 PVEThemes.py functionName");

			let expire = Ext.Date.add(new Date(), Ext.Date.YEAR, 10);
			Ext.util.Cookies.set(view.cookieName, vm.get('theme'), expire);
			window.location.reload();
		},"""
    #replace the functionName with the function variable
    buttonFunction = buttonFunction.replace("functionName", function.__name__)

    #add right under the controller array line
    themeEditWindow = themeEditWindow[:controllerLine + 13] + buttonFunction + themeEditWindow[controllerLine + 13:]

    #find the buttons array
    buttonsLine = themeEditWindow.find("items: [")

    #define our button
    button = """
    {
        xtype: 'button',
	    text: gettext('buttonName'),
	    handler: 'functionName',
        margin: 2,
	},
    """

    #replace the buttonName with the buttonName variable
    button = button.replace("buttonName", buttonName)
    #replace the functionName with the function variable
    button = button.replace("functionName", function.__name__)

    #add our button right under the buttons array line
    themeEditWindow = themeEditWindow[:buttonsLine + 9] + button + themeEditWindow[buttonsLine + 9:]

    #replace the fileContents with the new themeEditWindow
    fileContents = fileContents.replace(fileContents[themeEditWindowLine:themeEditWindowEnd], themeEditWindow)

    #write to the file
    f.seek(0)
    f.write(fileContents)
    f.truncate()
    f.close()

def removeSubscriptionNotice():
    print("Removing subscription notice from the PVE web interface...")
    #load the proxmoxlib.js file
    f = open(proxmoxLibLocation, "r+", encoding="utf8")
    fileContents = f.read()

    #find the no sub text
    noSub = fileContents.find("title: gettext('No valid subscription'),")

    previousLine = fileContents.rfind("\n", 0, noSub)
    previousLineStart = fileContents.rfind("\n", 0, previousLine)

    #Find the Ext.Msg.show({ in the previous line
    msgShow = fileContents.rfind("Ext.Msg.show({", previousLineStart, previousLine)
    
    #if the no sub text is not found, then the subscription notice has already been removed
    if msgShow == -1:
        print("Subscription notice already removed...")
        return

    #replace the Ext.Msg.show({ above noSub with void({
    fileContents = fileContents[:msgShow] + "void({" + fileContents[msgShow + 14:]

    #write to the file
    f.seek(0)
    f.write(fileContents)
    f.truncate()
    f.close()

def addZFSBar():
    print("Adding ZFS bar to the PVE web interface...")
    #open the pvemanagerlib.js file
    f = open(pvemanagerlibLocation, "r+", encoding="utf8")
    #read the file
    fileContents = f.read()

    defineLineStartSTR = "Ext.define('PVE.node.StatusView', {"
    defineLineStart = fileContents.find(defineLineStartSTR)
    defineLineEnd = fileContents.find("});", defineLineStart)
    #get the define
    define = fileContents[defineLineStart:defineLineEnd]

    #find the items array
    itemLineStartSTR = "items: ["
    itemLineStart = define.find(itemLineStartSTR)
    itemLineEndSTR = """},
    ],

    """
    itemLineEnd = fileContents.find(itemLineEndSTR, itemLineStart)

    #get the items array
    items = define[itemLineStart + len(itemLineStartSTR):itemLineEnd]

    #get the memory bar
    memoryBar = items.find("itemId: 'memory',")
    memoryBarEnd = items.find("},", memoryBar)

    #define our item
    item = """
    {
	    iconCls: 'fa fa-fw pmx-itype-icon-memory pmx-icon',
	    itemId: 'arc',
	    title: "ZFS ARC size",
		valueField: 'arc',
	    maxField: 'arc',
		renderer: function(record) {
			//check if the record exists
			if (record.used) {
				return Proxmox.Utils.render_node_size_usage(record);
			} else {
				localRecord = {
					used: 0,
					total: 100,
				};
				//make invisible if the record does not exist
				this.title = "ZFS Arc size (not available)";
				return Proxmox.Utils.render_node_size_usage(localRecord);
			}
		},
	},"""

    #add the item right under the memory bar item
    items = items[:memoryBarEnd + 2] + item + items[memoryBarEnd + 2:]

    define = define[:itemLineStart + len(itemLineStartSTR)] + items + define[itemLineEnd + len(itemLineEndSTR):]

    fileContents = fileContents.replace(fileContents[defineLineStart:defineLineEnd], define)

    #write to the file
    f.seek(0)
    f.write(fileContents)
    f.truncate()
    f.close()

    #modify the api to get the ZFS ARC size
    f = open(API2_Nodes, "r+", encoding="utf8")
    fileContents = f.read()

    resSTR = "my $res = {\n\t    uptime => 0,\n\t    idle => 0,\n\t};"

    #find the line after resSTR
    #resLine = fileContents.find(resSTR) + len(resSTR)

    #print(fileContents[resLine - 100:resLine + 100])

    appendStr = """
        open(my $fh, '<', '/proc/spl/kstat/zfs/arcstats') or die "Failed to open file: $!";

        my $arcused = 0;
        my $arctotal = 0;

        while (my $line = <$fh>) {
            if ($line =~ /^size/) {
                my @fields = split(' ', $line);
                $arcused = $fields[2];
            }
            elsif ($line =~ /^c_max/) {
                my @fields = split(' ', $line);
                $arctotal = $fields[2];
            }
        }
        close($fh);

        $res->{arc} = {
            used => $arcused,
            total => $arctotal,
        };

        my $meminfoC = PVE::ProcFSTools::read_meminfo();
        $res->{memoryreal} = {
            free => $meminfoC->{memfree} - $arcused,
            total => $meminfoC->{memtotal},
            used => $meminfoC->{memused} - $arcused,
        };
    """

    fileContents = fileContents.replace(resSTR, resSTR + appendStr)

    f.seek(0)
    f.write(fileContents)
    f.truncate()
    f.close()

    #reload the api service
    os.system("pveproxy restart")

def install():
    compileSassThemes()
    #check if the user already had the UI control enabled by seeing if sendShellCommand is in the proxmoxlib.js file
    buttonControl = False
    if "sendShellCommand" in open(proxmoxLibLocation, "r", encoding="utf8").read():
        buttonControl = True

    reinstallProxmoxWidgetToolkit()
    patchThemes()
    if buttonControl:
        installUIOptions()

    print("Done! Clear your browser cache and refresh the page to see the new themes.")

def installUIOptions():
    print("Patching in websocket system...")
    #append websocketHandler.js to the end of proxmoxlib.js
    f = open(proxmoxLibLocation, "a", encoding="utf8")
    wsh = open("websocketHandler.js", "r", encoding="utf8")
    f.write(wsh.read())
    wsh.close()
    f.close()

    addButton(uninstall, "Uninstall PVEThemes")
    addButton(install, "Reinstall PVEThemes")
    addButton(update, "Update PVEThemes")
    addZFSBar()
    removeSubscriptionNotice()

def uninstall():
    reinstallProxmoxWidgetToolkit()
    print("Custom themes uninstalled.")

def update():
    #git pull self
    os.system("git pull --quiet")
    #exit and run self
    os.system("python3 PVEThemes.py install")

def main():
    print("PVEThemes Installer")
    print("By: Happyrobot33")
    print("Select an option:")
    print("-------------------")
    print("0. Exit")
    print("1. uninstall")
    print("2. install")
    print("3. update")
    print("4. compile sass themes")
    print("5. enable UI tweaks")
    print("6. disable UI tweaks")
    print("-------------------")
    choice = input("Enter a number: ")

    if choice == "0":
        exit()
    elif choice == "1":
        uninstall()
    elif choice == "2":
        install()
    elif choice == "3":
        update()
    elif choice == "4":
        compileSassThemes()
    elif choice == "5":
        choice2 = input("Are you sure you want to enable the UI tweaks? This will add buttons to your UI to update the theme system, but will also modify more files to accomplish this, possibly lowering stability (y/n): ")
        if choice2 == "y":
            installUIOptions()
        else:
            main()
    elif choice == "6":
        reinstallProxmoxWidgetToolkit()
        install()
    else:
        print("Invalid choice")
        main()

if __name__ == "__main__":
    #if there is any args, call the function in the arg instead
    if len(sys.argv) > 1:
        globals()[sys.argv[1]]()
    else:
        main()
