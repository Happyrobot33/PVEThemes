import os

proxmoxLibLocation = "samples/proxmoxlib.js"

def modifyThemeMap(themeFileName, themeTitle):
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

#This file patches the appropriate files to add all of the themes

#DEVELOPMENT PURPOSES
#copy the backup proxmoxlib.js file to the normal proxmoxlib.js file
#fA = open("samples/proxmoxlibcopy.js", "r", encoding="utf8")
#fileContents = fA.read()
#fA.close()
#f2 = open("samples/proxmoxlib.js", "w+", encoding="utf8")
#f2.write(fileContents)
#f2.close()
#####

#if on linux, we should be on a proxmox machine, so apt reinstall proxmox-widget-toolkit to get the original proxmoxlib.js file
if os.name == "posix":
    print("Reinstalling proxmox-widget-toolkit...")
    os.system("apt reinstall proxmox-widget-toolkit")
    proxmoxLibLocation = "/usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js"

#get all of the themes to install in the themes folder
themes = os.listdir("themes")

for theme in themes:
    print("Patching " + theme + " into proxmoxlib.js...")

    #read in the first line of the theme file
    f = open("themes/" + theme, "r", encoding="utf8")
    firstLine = f.readline()

    #extract the theme name from the first line comment, which is between /* and */
    themeTitle = firstLine[firstLine.find("/*") + 2:firstLine.find("*/")]

    #get the theme file name without the .css extension and missing the theme- prefix
    themeFileName = theme[theme.find("theme-") + 6:theme.find(".css")]

    modifyThemeMap(themeFileName, themeTitle)

if os.name == "posix":
    #copy all the themes into the themes folder
    os.system("cp themes/* /usr/share/javascript/proxmox-widget-toolkit/themes")

print("Done installing themes!")
