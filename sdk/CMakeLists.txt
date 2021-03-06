PROJECT(PARKINGCLOUDAPI)
cmake_minimum_required(VERSION 2.6)

MESSAGE( STATUS "PROJECT_SOURCE_DIR=" ${PROJECT_SOURCE_DIR})
MESSAGE( STATUS "PROJECT_BINARY_DIR=" ${PROJECT_BINARY_DIR})

SET(CMAKE_BUILD_TYPE RELEASE)

SET(OS_TYPE linux)

IF(${CMAKE_BUILD_TYPE} MATCHES "RELEASE")
	SET(BUILDTYPE_NAME release)
ELSE()
	SET(BUILDTYPE_NAME debug)
ENDIF()

IF(${CMAKE_SYSTEM_VERSION} MATCHES ".*i686.*")
	SET(OS_BIT_NUM 32)
ELSE()
	SET(OS_BIT_NUM 64)
ENDIF()
MESSAGE( STATUS "OS_BIT_NUM=" ${OS_BIT_NUM})

SET(BUILD_CLASSIFIER "l${OS_BIT_NUM}_${BUILDTYPE_NAME}")

SET(OS_LIB_DIR ${OS_TYPE})
IF(OS_TYPE MATCHES linux)
	SET(OS_LIB_DIR ${OS_TYPE}${OS_BIT_NUM})
ENDIF(OS_TYPE MATCHES linux)

IF(OS_BIT_NUM MATCHES 64)
	SET (OS_BIT_NUM 64)
	set(CMAKE_C_FLAGS "-std=c99 -O2 -Wall -ggdb -DOPENSSL_NO_SHA -fvisibility=hidden") 
	SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O2 -Wall -ggdb -D_WIN64  -DOPENSSL_NO_SHA")
	SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O2 -ggdb -Wall -D_WIN64 -DOPENSSL_NO_SHA")
ELSE(OS_BIT_NUM MATCHES 32)
	SET (OS_BIT_NUM 32)
	set(CMAKE_C_FLAGS "-std=c99 -O2 -Wall -ggdb -DOPENSSL_NO_SHA -fvisibility=hidden") 
	SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O2 -Wall -ggdb ")
	SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O2 -ggdb -Wall")
ENDIF(OS_BIT_NUM MATCHES 64)


MESSAGE( STATUS "OS_LIB_DIR=" ${OS_LIB_DIR} )
MESSAGE( STATUS "OS_TYPE=" ${OS_TYPE})

# Develop Dir
SET(REPORT ${PROJECT_SOURCE_DIR})

SET(LIB_NAME_MOSQUITTO mosquitto)

# Deploy dir
SET(DEPLOY_DIR ${PROJECT_SOURCE_DIR}/output/${OS_BIT_NUM})
MESSAGE( STATUS "DEPLOY_DIR=" ${DEPLOY_DIR})

SET(PARKINGCLOUDAPI_SRCLIST ${PROJECT_SOURCE_DIR}/api/parkcloudsession.c ${PROJECT_SOURCE_DIR}/api/cJSON.c)
MESSAGE( STATUS "PARKINGCLOUDAPI_SRCLIST=" ${PARKINGCLOUDAPI_SRCLIST})

SET(PARKINGCLOUDAPI_INCLIST ${PROJECT_SOURCE_DIR}/api/parkcloudsession.h)
MESSAGE( STATUS "PARKINGCLOUDAPI_INCLIST=" ${PARKINGCLOUDAPI_INCLIST})

SET(PARKINGCLOUDAPITEST_SRCLIST ${PROJECT_SOURCE_DIR}/apitest/apitest.cpp)
MESSAGE( STATUS "PARKINGCLOUDAPITEST_SRCLIST=" ${PARKINGCLOUDAPITEST_SRCLIST})

INCLUDE_DIRECTORIES(
${PROJECT_SOURCE_DIR}/api
${PROJECT_SOURCE_DIR}/apitest/apitest
)

set(CMAKE_SHARED_LINKER_FLAGS "-Wl")
SET(LIBRARY_OUTPUT_PATH ${DEPLOY_DIR})
ADD_LIBRARY( parkingcloudapi SHARED ${PARKINGCLOUDAPI_SRCLIST} )
TARGET_LINK_LIBRARIES( parkingcloudapi ${LIB_NAME_MOSQUITTO} )


ADD_CUSTOM_COMMAND(TARGET parkingcloudapi 
POST_BUILD
COMMAND cp ${PARKINGCLOUDAPI_INCLIST} ${DEPLOY_DIR}
)



SET(EXECUTABLE_OUTPUT_PATH ${DEPLOY_DIR})
ADD_EXECUTABLE(parkingcloudapitest ${PARKINGCLOUDAPITEST_SRCLIST})
TARGET_LINK_LIBRARIES( parkingcloudapitest parkingcloudapi )




