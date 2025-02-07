#!/bin/sh

ENGINE_DIR=$1  #path to engine
PATH_TO="/home/jovyan/js_generator/"


FOLDER_NAME=$(basename "$ENGINE_DIR")

if [ "$FOLDER_NAME" = "ChakraCore" ]; then
  EXEC_PATH="/out/Release/ch"
  LCOV_PATH="/out/Release/"
  LOCATION=${PATH_TO}"CK_FIRST/"
elif [ "$FOLDER_NAME" = "WebKit" ]; then
  EXEC_PATH="/CovBuild/bin/jsc"
  LCOV_PATH="/CovBuild/"
  LOCATION=${PATH_TO}"JSC_FIRST/"
else
  echo "Not correct folder."
  exit
fi
echo ${ENGINE_DIR}${LCOV_PATH}
echo ${LOCATION}
find ${ENGINE_DIR}${LCOV_PATH} -name '*.c' -exec cp -t ${LOCATION} {} + 
find ${ENGINE_DIR}${LCOV_PATH} -name '*.gcno' -exec cp -t ${LOCATION} {} + 
find ${ENGINE_DIR}${LCOV_PATH} -name '*.gcda' -exec cp -t ${LOCATION} {} + -exec sh -c 'for f; do echo "$f" >> "$LOCATION"/_gcda_files.txt; done' _ {} +
find ${ENGINE_DIR}${LCOV_PATH} -name '*.gcda' -exec mv -t ${LOCATION} {} + 
find ${ENGINE_DIR}${LCOV_PATH} -name '*.h' -exec cp -t ${LOCATION} {} +

echo "Конвертация файла покрытия" 
fastcov -C ${LOCATION}cov.info -o ${LOCATION}cov_${JS_NAME}.json
lcov --directory ${ENGINE_DIR}${LCOV_PATH} --gcov-tool ${PATH_TO}llvm-gcov.sh --capture -o ${LOCATION}cov.info

echo "Генерация html-файла"
genhtml ${LOCATION}cov.info -o ${LOCATION}lcov_out
exit
