#!/bin/sh

ENGINE_DIR=$1  #path to engine
JS_FILE=$2    #path to js_file
JS_NAME=$(basename "$JS_FILE")
PATH_TO="/home/jovyan/js_generator/"

FOLDER_NAME=$(basename $ENGINE_DIR)
if [ "$FOLDER_NAME" = "ChakraCore" ]; then
  EXEC_PATH="out/Release/ch"
  LCOV_PATH="out/Release/"
  COV_FIRST=${PATH_TO}"CK_FIRST/"
  LOCATION=${PATH_TO}"CK_NEXT/"
elif [ "$FOLDER_NAME" = "WebKit" ]; then
  EXEC_PATH="CovBuild/bin/jsc"
  LCOV_PATH="CovBuild/"
  COV_FIRST=${PATH_TO}"JSC_FIRST/"
  LOCATION=${PATH_TO}"JSC_NEXT/"
elif [ "$FOLDER_NAME" = "jerryscript" ]; then
  EXEC_PATH="build/bin/jerry"
  LCOV_PATH="build/"
  COV_FIRST=${PATH_TO}"jerry_FIRST/"
  LOCATION=${PATH_TO}"jerry_NEXT/"
elif [ "$FOLDER_NAME" = "v8" ]; then
  EXEC_PATH="fuzzbuild/d8"
  LCOV_PATH="fuzzbuild/"
  COV_FIRST=${PATH_TO}"V8_FIRST/"
  LOCATION=${PATH_TO}"V8_NEXT/"
else
  echo "Not correct folder."
  exit
fi
#make new dict for next cov
if [ -d "$LOCATION" ]
then
    rm -R $LOCATION
fi
mkdir $LOCATION

copy first files to engine path
cp -r ${COV_FIRST}* ${ENGINE_DIR}${LCOV_PATH}

echo "Запуск seed'a"
${ENGINE_DIR}${EXEC_PATH} ${JS_FILE}

find ${ENGINE_DIR}${LCOV_PATH} -name '*.gcda' -exec cp -t ${LOCATION} {} + -exec sh -c 'for f; do echo "$f" >> "$LOCATION"/_gcda_files.txt; done' _ {} +
find ${ENGINE_DIR}${LCOV_PATH} -name '*.gcda' -exec cp -t ${LOCATION} {} + 

echo "Формирование покрытия"
lcov --directory ${ENGINE_DIR}${LCOV_PATH} --gcov-tool ${PATH_TO}llvm-gcov.sh --capture -o ${LOCATION}_cov.info --quiet 
lcov --summary ${LOCATION}_cov.info
exit


fastcov --gcov gcov-11 -d ${ENGINE_DIR}${LCOV_PATH} --lcov -o ${LOCATION}_cov.info --dump-statistic
echo "Конвертация файла покрытия" 
fastcov -C ${LOCATION}_cov.info -o ${LOCATION}_cov.json --dump-statistic
echo "Генерация html-файла"
genhtml ${LOCATION}_cov.info -o ${LOCATION}lcov_out
