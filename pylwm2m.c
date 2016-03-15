/*
 * Copyright (c) 2016, Luc Yriarte
 * BSD License <http://www.opensource.org/licenses/bsd-license.php>
 * 
 * Author:
 * Luc Yriarte <luc.yriarte@thingagora.org>
 */

#include <Python.h>
#include <stdlib.h>
#include <stdio.h>

#include "pylwm2m.h"



/*
 * utilities
 */ 

static void prv_lwm2m_context_cleanup(pylwm2m_context_t * pylwm2mH) {
	if (pylwm2mH->lwm2mH) {
		lwm2m_close(pylwm2mH->lwm2mH);
    }

	Py_XDECREF(pylwm2mH->userData);
	Py_XDECREF(pylwm2mH->monitoringResult.resultCb);
	Py_XDECREF(pylwm2mH->monitoringResult.resultData);
	free(pylwm2mH);
}

int prv_lwm2m_uri_dump(lwm2m_uri_t * uriP, char * uriBuf) {
TRACE("%s %p %p\n",__FUNCTION__, uriP, uriBuf);
	uriBuf[0] = '\0';
	if (uriP) {
		sprintf(uriBuf,"/%u",(unsigned int)uriP->objectId);
		if (LWM2M_URI_IS_SET_INSTANCE(uriP)) {
			sprintf(uriBuf+strlen(uriBuf),"/%u",(unsigned int)uriP->instanceId);
			if (LWM2M_URI_IS_SET_RESOURCE(uriP)) {
				sprintf(uriBuf+strlen(uriBuf),"/%u",(unsigned int)uriP->resourceId);
			}
		}
	}
	return strlen(uriBuf);
}


/*
 * comms callbacks
 */ 

static PyObject* buffer_send_cb = NULL;
static PyObject* session_is_equal_cb = NULL;

uint8_t
lwm2m_buffer_send(void* sessionH, uint8_t* buffer, size_t length, void* userData)
{
    pylwm2m_context_t* pylwm2mH = (pylwm2m_context_t*) userData;
    if (pylwm2mH == NULL) {
        return COAP_500_INTERNAL_SERVER_ERROR;
    }

    PyObject* pyresult = PyObject_CallFunction(
        buffer_send_cb,
        "Os#O",
        sessionH,
        buffer,
        (int) length,
        pylwm2mH->userData);

    if (pyresult == NULL) {
        return COAP_500_INTERNAL_SERVER_ERROR;
    }

    uint8_t result = (uint8_t) PyInt_AsLong(pyresult);
    Py_DECREF(pyresult);
    return result;
}


bool
lwm2m_session_is_equal(void* session1, void* session2, void* userData)
{
    
    pylwm2m_context_t* pylwm2mH = (pylwm2m_context_t*) userData;
    if (pylwm2mH == NULL) {
        return 0;
    }

    PyObject* py_result = PyObject_CallFunction(
        session_is_equal_cb,
        "OOO",
        session1,
        session2,
        pylwm2mH->userData);

    if (py_result == NULL) {
        PyErr_Clear();
        return 0;
    }

    bool result = PyObject_IsTrue(py_result);
    Py_DECREF(py_result);

    return result;
}


/*
 * lwm2m API wrapper
 */ 

PyObject*
pylwm2m_set_transport_callbacks(PyObject* self, PyObject* args) {
    PyObject* new_buffer_send_cb = NULL;
    PyObject* new_session_equal_cb = NULL;

    if (!PyArg_ParseTuple(args, "OO", &new_buffer_send_cb, &new_session_equal_cb)) {
        return NULL;
    }

    if (PyCallable_Check(new_buffer_send_cb) == 0) {
        return PyErr_Format(PyExc_ValueError, "Buffer send callback not callable");
    }

    if (PyCallable_Check(new_session_equal_cb) == 0) {
        return PyErr_Format(PyExc_ValueError, "Session is equal callback not callable");
    }

    Py_XDECREF(buffer_send_cb);
    Py_XDECREF(session_is_equal_cb);

    buffer_send_cb = new_buffer_send_cb;
    session_is_equal_cb = new_session_equal_cb;

    Py_INCREF(buffer_send_cb);
    Py_INCREF(session_is_equal_cb);

    Py_RETURN_NONE;
}

PyObject*
pylwm2m_init(PyObject *self, PyObject *args) {
    if ((buffer_send_cb == NULL) || (session_is_equal_cb == NULL)) {
        return PyErr_Format(PyExc_Exception, "transport callbacks not set yet");
    }

	pylwm2m_context_t* pylwm2mH = (pylwm2m_context_t *) malloc(sizeof(struct _pylwm2m_context_));
    if (pylwm2mH == NULL) {
        return PyErr_NoMemory();
    }

	memset(pylwm2mH, 0, sizeof(struct _pylwm2m_context_));
	pylwm2mH->lwm2mH = lwm2m_init((void *)pylwm2mH);

    if (pylwm2mH->lwm2mH == NULL) {
        free(pylwm2mH);
        return PyErr_Format(PyExc_Exception, "Unknown error in lwm2m_init");
    }

    if (!PyArg_ParseTuple(args, "O", &pylwm2mH->userData)) {
        free(pylwm2mH);
        return NULL;
    }

    Py_INCREF(pylwm2mH->userData);
	return PyCapsule_New((void *) pylwm2mH, NULL, NULL);
}

PyObject * pylwm2m_close(PyObject *self, PyObject *args) {
TRACE("%s %p %p\n",__FUNCTION__, self, args);
	pylwm2m_context_t * pylwm2mH = NULL;
	PyObject *pylwm2mHCap = NULL;
	if (!PyArg_ParseTuple(args, "O", &pylwm2mHCap)) {
		return NULL;
	}
	pylwm2mH = PyCapsule_GetPointer(pylwm2mHCap, NULL);
	prv_lwm2m_context_cleanup(pylwm2mH);
	return Py_None;
}

PyObject * pylwm2m_step(PyObject *self, PyObject *args) {
TRACE("%s %p %p\n",__FUNCTION__, self, args);
	pylwm2m_context_t * pylwm2mH = NULL;
	PyObject *pylwm2mHCap = NULL;
	time_t timeout = (time_t) -1;
	if (!PyArg_ParseTuple(args, "O", &pylwm2mHCap)) {
		return NULL;
	}
	pylwm2mH = PyCapsule_GetPointer(pylwm2mHCap, NULL);
TRACE("lwm2m_step %p %d\n",pylwm2mH->lwm2mH, (int)timeout);
	lwm2m_step(pylwm2mH->lwm2mH, &timeout);
TRACE("lwm2m_step result: %d\n", (int)timeout);
	return Py_BuildValue("i", timeout);
}

PyObject * pylwm2m_handle_packet(PyObject *self, PyObject *args) {
TRACE("%s %p %p\n",__FUNCTION__, self, args);
	pylwm2m_context_t * pylwm2mH = NULL;
	PyObject *pylwm2mHCap = NULL;
	uint8_t *buffer = NULL;
	int length = -1;
	PyObject *fromSessionH = NULL;
	if (!PyArg_ParseTuple(args, "Os#iO", &pylwm2mHCap, &buffer, &length, &length, &fromSessionH)) {
		return NULL;
	}
	pylwm2mH = PyCapsule_GetPointer(pylwm2mHCap, NULL);
TRACE("lwm2m_handle_packet %p %p %d %p\n",pylwm2mH->lwm2mH, buffer, length, fromSessionH);
	lwm2m_handle_packet(pylwm2mH->lwm2mH, buffer, length, fromSessionH);
	return Py_None;
}


/*
 * Python module management
 */ 

static PyMethodDef lwm2mMethods[] = {
    {"lwm2m_set_transport_callbacks", pylwm2m_set_transport_callbacks, METH_VARARGS,
        "lwm2m_set_transport_callbacks(buffer_send_cb, session_eq_cb)"},
    {"lwm2m_init", pylwm2m_init, METH_VARARGS, 
		"lwm2m_init(userData) - > handle"},
    {"lwm2m_close", pylwm2m_close, METH_VARARGS, 
		"lwm2m_close(handle)"},
    {"lwm2m_step", pylwm2m_step, METH_VARARGS, 
		"lwm2m_step(handle) -> timeStep"},
    {"lwm2m_handle_packet", pylwm2m_handle_packet, METH_VARARGS, 
		"lwm2m_handle_packet(handle, data, length, address)"},
    {"lwm2m_set_monitoring_callback", pylwm2m_set_monitoring_callback, METH_VARARGS, 
		"lwm2m_set_monitoring_callback(handle, monitoringCallback, userData)"},
    {"lwm2m_get_client_info", pylwm2m_get_client_info, METH_VARARGS, 
		"lwm2m_get_client_info(handle, clientID) -> (name, uris)"},
    {"lwm2m_dm_read", pylwm2m_dm_read, METH_VARARGS, 
		"lwm2m_dm_read(handle, clientID, uriStr, resultCallback, userData) -> error"},
    {"lwm2m_dm_write", pylwm2m_dm_write, METH_VARARGS, 
		"lwm2m_dm_write(handle, clientID, uriStr, format, buffer, length, resultCallback, userData) -> error"},
    {"lwm2m_dm_execute", pylwm2m_dm_execute, METH_VARARGS, 
		"lwm2m_dm_execute(handle, clientID, uriStr, format, buffer, length, resultCallback, userData) -> error"},
    {"lwm2m_dm_create", pylwm2m_dm_create, METH_VARARGS, 
		"lwm2m_dm_create(handle, clientID, uriStr, format, buffer, length, resultCallback, userData) -> error"},
    {"lwm2m_dm_delete", pylwm2m_dm_delete, METH_VARARGS, 
		"lwm2m_dm_delete(handle, clientID, uriStr, resultCallback, userData) -> error"},
    {"lwm2m_observe", pylwm2m_observe, METH_VARARGS, 
		NULL},
    {"lwm2m_observe_cancel", pylwm2m_observe_cancel, METH_VARARGS, 
		NULL},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
initlwm2m(void)
{
    (void) Py_InitModule("lwm2m", lwm2mMethods);
}
