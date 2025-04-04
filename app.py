import sys
import os
import cv2
import numpy as np
import face_recognition
from datetime import datetime, time, timedelta
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QStatusBar, QTableWidget, QTableWidgetItem,
    QHeaderView, QComboBox, QSpinBox, QMessageBox, QInputDialog,
    QDialog, QListWidget, QGroupBox, QFrame, QSizePolicy, QGridLayout, QCheckBox
)
from PyQt5.QtCore import QTimer, Qt, QThread, pyqtSignal, QObject
from PyQt5.QtGui import QImage, QPixmap, QFont, QColor, QPalette, QIcon
import pickle
import csv
import winsound
from twilio.rest import Client  # For SMS alerts

# Configuration
CONFIG = {
    "ENTRY_POINTS": ["Main Door", "Back Gate", "Side Entrance"],
    "RESTRICTED_HOURS": (time(22, 0), time(6, 0)),  # 10PM-6AM
    "MAX_OCCUPANCY": 15,
    "ALERT_COOLDOWN": 300,  # 5 minutes
    "DETECTION_COOLDOWN": 300,  # 5 minutes between detections of same person
    "DATA_DIR": "security_data",
    "KNOWN_FACES_FILE": "known_faces.dat",
    "ACCESS_LOG": "access_log.csv",
    "UNAUTHORIZED_DIR": "unauthorized_entries",
    "TWILIO_ACCOUNT_SID": "",  # Replace with your Twilio credentials
    "TWILIO_AUTH_TOKEN": "",
    "TWILIO_PHONE_NUMBER": "+1 220 902 2545",  # Your Twilio phone number
    "ADMIN_PHONE_NUMBER": ""  # Admin phone number to receive alerts
}

# Create directories if they don't exist
os.makedirs(CONFIG["DATA_DIR"], exist_ok=True)
os.makedirs(os.path.join(CONFIG["DATA_DIR"], CONFIG["UNAUTHORIZED_DIR"]), exist_ok=True)

# Custom color palette with olive green
COLORS = {
    "primary": "#808000",  # Olive Green
    "secondary": "#556B2F",  # Dark Olive Green
    "danger": "#B22222",    # Firebrick
    "dark": "#2F4F4F",      # Dark Slate Gray
    "light": "#F5F5DC",     # Beige
    "background": "#696969"  # Dim Gray
}

class FaceDetector(QObject):
    detection_complete = pyqtSignal(np.ndarray, list, list)
    finished = pyqtSignal()
    detect_signal = pyqtSignal(np.ndarray)

    def __init__(self, known_faces, known_names):
        super().__init__()
        self.known_faces = known_faces
        self.known_names = known_names
        self._is_running = False
        self.detect_signal.connect(self.detect)

    def detect(self, frame):
        if not self._is_running:
            self._is_running = True
            try:
                rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                face_locations = face_recognition.face_locations(rgb_frame)
                face_encodings = face_recognition.face_encodings(rgb_frame, face_locations)
                
                face_names = []
                for face_encoding in face_encodings:
                    matches = face_recognition.compare_faces(self.known_faces, face_encoding)
                    name = "Unknown"
                    
                    if True in matches:
                        face_distances = face_recognition.face_distance(self.known_faces, face_encoding)
                        best_match_index = np.argmin(face_distances)
                        name = self.known_names[best_match_index]
                    
                    face_names.append(name)
                
                self.detection_complete.emit(frame, face_locations, face_names)
            except Exception as e:
                print(f"Detection error: {e}")
            finally:
                self._is_running = False
                self.finished.emit()

class StyledButton(QPushButton):
    def __init__(self, text, color, parent=None):
        super().__init__(text, parent)
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {color};
                color: black;
                border: 2px solid {self._darken_color(color)};
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
                font-size: 12px;
            }}
            QPushButton:hover {{
                background-color: {self._darken_color(color, 0.9)};
            }}
            QPushButton:pressed {{
                background-color: {self._darken_color(color, 0.8)};
            }}
        """)
        self.setCursor(Qt.PointingHandCursor)
        
    def _darken_color(self, hex_color, factor=0.85):
        """Darken a hex color by a factor (0-1)"""
        color = QColor(hex_color)
        return color.darker(int(100 + (100 * (1 - factor)))).name()

class UnauthorizedEntrySystem(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Security Access Control System")
        self.setGeometry(100, 100, 1280, 800)
        
        # Set application style
        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: {COLORS['background']};
                color: {COLORS['light']};
            }}
            QTabWidget::pane {{
                border: 1px solid {COLORS['dark']};
                border-radius: 4px;
                padding: 4px;
                background: {COLORS['dark']};
            }}
            QTabBar::tab {{
                background: {COLORS['dark']};
                color: {COLORS['light']};
                padding: 8px 16px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                margin-right: 2px;
                font-weight: bold;
            }}
            QTabBar::tab:selected {{
                background: {COLORS['primary']};
                color: black;
            }}
            QGroupBox {{
                border: 2px solid {COLORS['primary']};
                border-radius: 4px;
                margin-top: 10px;
                padding-top: 15px;
                font-weight: bold;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px;
                color: {COLORS['primary']};
            }}
            QTableWidget {{
                background-color: {COLORS['dark']};
                color: {COLORS['light']};
                gridline-color: {COLORS['primary']};
                border: 1px solid {COLORS['primary']};
                font-size: 12px;
            }}
            QHeaderView::section {{
                background-color: {COLORS['primary']};
                color: black;
                padding: 4px;
                border: none;
                font-weight: bold;
            }}
            QStatusBar {{
                background-color: {COLORS['dark']};
                color: {COLORS['light']};
                font-weight: bold;
            }}
            QLabel {{
                font-weight: bold;
            }}
            QComboBox, QSpinBox {{
                background-color: {COLORS['light']};
                color: black;
                border: 1px solid {COLORS['primary']};
                padding: 3px;
                font-weight: bold;
            }}
            QCheckBox {{
                color: {COLORS['light']};
                font-weight: bold;
            }}
            QCheckBox::indicator {{
                width: 20px;
                height: 20px;
            }}
        """)
        
        # System state
        self.known_faces = []
        self.known_names = []
        self.unknown_face_log = {}
        self.last_alert_time = None
        self.current_occupancy = 0
        self.current_location = CONFIG["ENTRY_POINTS"][0]
        self.camera_active = False
        self.cap = None
        self.detected_persons = {}  # Track when persons were last detected
        self.sms_alerts_enabled = False
        self.twilio_client = None
        
        # Initialize Twilio client if credentials are provided
        if (CONFIG["TWILIO_ACCOUNT_SID"] and CONFIG["TWILIO_AUTH_TOKEN"] and
            CONFIG["TWILIO_PHONE_NUMBER"] and CONFIG["ADMIN_PHONE_NUMBER"]):
            try:
                self.twilio_client = Client(CONFIG["TWILIO_ACCOUNT_SID"], CONFIG["TWILIO_AUTH_TOKEN"])
                self.sms_alerts_enabled = True
            except Exception as e:
                print(f"Failed to initialize Twilio client: {e}")
        
        # Initialize UI
        self.init_ui()
        self.setup_face_detection()
        self.load_known_faces()

    def init_ui(self):
        """Initialize the main user interface"""
        self.tabs = QTabWidget()
        self.tabs.setFont(QFont("Segoe UI", 10))
        self.setCentralWidget(self.tabs)
        
        # Create tabs
        self.create_detection_tab()
        self.create_access_log_tab()
        self.create_control_tab()
        
        # Set window icon
        self.setWindowIcon(QIcon("security_icon.png"))  # Add your icon file

    def create_detection_tab(self):
        """Combined detection and admin tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Camera control group
        camera_control_group = QGroupBox("Camera Controls")
        camera_control_layout = QHBoxLayout()
        
        self.start_button = StyledButton("Start Camera", COLORS["secondary"])
        self.start_button.clicked.connect(self.start_camera)
        camera_control_layout.addWidget(self.start_button)
        
        self.stop_button = StyledButton("Stop Camera", COLORS["danger"])
        self.stop_button.clicked.connect(self.stop_camera)
        self.stop_button.setEnabled(False)
        camera_control_layout.addWidget(self.stop_button)
        
        camera_control_group.setLayout(camera_control_layout)
        layout.addWidget(camera_control_group)
        
        # Camera display group
        camera_group = QGroupBox("Live Camera Feed")
        camera_layout = QVBoxLayout()
        
        self.camera_display = QLabel()
        self.camera_display.setAlignment(Qt.AlignCenter)
        self.camera_display.setMinimumSize(640, 480)
        self.camera_display.setStyleSheet("background-color: black;")
        camera_layout.addWidget(self.camera_display)
        
        camera_group.setLayout(camera_layout)
        layout.addWidget(camera_group)
        
        # Admin functions group
        admin_group = QGroupBox("User Management")
        admin_layout = QGridLayout()
        
        self.register_button = StyledButton("Register New User", COLORS["primary"])
        self.register_button.clicked.connect(self.register_face)
        admin_layout.addWidget(self.register_button, 0, 0)
        
        self.view_faces_button = StyledButton("View Registered Users", COLORS["primary"])
        self.view_faces_button.clicked.connect(self.view_registered_faces)
        admin_layout.addWidget(self.view_faces_button, 0, 1)
        
        # SMS Alerts checkbox
        self.sms_checkbox = QCheckBox("Enable SMS Alerts")
        self.sms_checkbox.setChecked(self.sms_alerts_enabled)
        self.sms_checkbox.stateChanged.connect(self.toggle_sms_alerts)
        admin_layout.addWidget(self.sms_checkbox, 1, 0, 1, 2)
        
        admin_group.setLayout(admin_layout)
        layout.addWidget(admin_group)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.status_bar.setFont(QFont("Segoe UI", 9))
        layout.addWidget(self.status_bar)
        
        tab.setLayout(layout)
        self.tabs.addTab(tab, "Detection & Users")

    def create_access_log_tab(self):
        """Access logs tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)
        
        log_group = QGroupBox("Access Logs")
        log_layout = QVBoxLayout()
        
        self.access_log_table = QTableWidget()
        self.access_log_table.setColumnCount(5)
        self.access_log_table.setHorizontalHeaderLabels(
            ["Timestamp", "Location", "Name", "Status", "Details"]
        )
        self.access_log_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.access_log_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.access_log_table.setEditTriggers(QTableWidget.NoEditTriggers)
        
        # Load existing logs
        self.load_access_logs()
        
        log_layout.addWidget(self.access_log_table)
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)
        
        tab.setLayout(layout)
        self.tabs.addTab(tab, "Access Logs")

    def create_control_tab(self):
        """System control tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(15)
        
        # Location control group
        location_group = QGroupBox("Location Settings")
        location_layout = QVBoxLayout()
        
        location_layout.addWidget(QLabel("Monitoring Location:"))
        self.location_selector = QComboBox()
        self.location_selector.addItems(CONFIG["ENTRY_POINTS"])
        self.location_selector.currentTextChanged.connect(self.update_location)
        self.location_selector.setFont(QFont("Segoe UI", 10))
        location_layout.addWidget(self.location_selector)
        
        location_group.setLayout(location_layout)
        layout.addWidget(location_group)
        
        # Occupancy control group
        occupancy_group = QGroupBox("Occupancy Settings")
        occupancy_layout = QVBoxLayout()
        
        occupancy_layout.addWidget(QLabel("Max Occupancy:"))
        self.occupancy_spinner = QSpinBox()
        self.occupancy_spinner.setRange(1, 100)
        self.occupancy_spinner.setValue(CONFIG["MAX_OCCUPANCY"])
        self.occupancy_spinner.setFont(QFont("Segoe UI", 10))
        occupancy_layout.addWidget(self.occupancy_spinner)
        
        occupancy_group.setLayout(occupancy_layout)
        layout.addWidget(occupancy_group)
        
        # Alert test button
        self.test_alert_button = StyledButton("Test Alert System", COLORS["danger"])
        self.test_alert_button.clicked.connect(self.test_alert)
        layout.addWidget(self.test_alert_button, alignment=Qt.AlignCenter)
        
        # Add stretch to push everything up
        layout.addStretch()
        
        tab.setLayout(layout)
        self.tabs.addTab(tab, "System Control")

    def toggle_sms_alerts(self, state):
        """Enable or disable SMS alerts"""
        self.sms_alerts_enabled = state == Qt.Checked
        if self.sms_alerts_enabled and not self.twilio_client:
            QMessageBox.warning(self, "SMS Alert Error", 
                               "Twilio credentials not properly configured. SMS alerts will not work.")

    def send_sms_alert(self, message):
        """Send SMS alert using Twilio"""
        if not self.sms_alerts_enabled or not self.twilio_client:
            return
            
        try:
            self.twilio_client.messages.create(
                body=message,
                from_=CONFIG["TWILIO_PHONE_NUMBER"],
                to=CONFIG["ADMIN_PHONE_NUMBER"]
            )
            self.status_bar.showMessage("SMS alert sent", 3000)
        except Exception as e:
            print(f"Failed to send SMS: {e}")
            self.status_bar.showMessage("Failed to send SMS alert", 3000)

    def start_camera(self):
        """Initialize and start video capture"""
        if not self.camera_active:
            self.cap = cv2.VideoCapture(0)
            if not self.cap.isOpened():
                QMessageBox.critical(self, "Error", "Failed to initialize camera!")
                return
            
            self.camera_active = True
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            
            self.timer = QTimer()
            self.timer.timeout.connect(self.process_frame)
            self.timer.start(30)  # ~30 FPS
            
            self.status_bar.showMessage("Camera started", 3000)

    def stop_camera(self):
        """Stop video capture"""
        if self.camera_active:
            self.timer.stop()
            if self.cap and self.cap.isOpened():
                self.cap.release()
            self.camera_active = False
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            
            # Clear the display
            self.camera_display.clear()
            self.camera_display.setText("Camera stopped")
            self.camera_display.setStyleSheet("background-color: black; color: white; font-weight: bold;")
            
            self.status_bar.showMessage("Camera stopped", 3000)

    def process_frame(self):
        """Process each camera frame"""
        if not self.camera_active:
            return
            
        ret, frame = self.cap.read()
        if not ret:
            return
        
        # Display frame immediately
        self.display_frame(frame)
        
        # Start face detection if worker is available
        if hasattr(self, 'face_worker') and not self.face_worker._is_running:
            self.face_worker.detect_signal.emit(frame.copy())

    def handle_detection_results(self, frame, face_locations, face_names):
        """Handle results from face detection"""
        self.current_occupancy = len(face_names)
        now = datetime.now()
        
        for (top, right, bottom, left), name in zip(face_locations, face_names):
            status = "Authorized"
            details = ""
            
            # Check if this person was recently detected
            if name in self.detected_persons:
                last_detection = self.detected_persons[name]
                if (now - last_detection).total_seconds() < CONFIG["DETECTION_COOLDOWN"]:
                    continue  # Skip this detection as it's within cooldown period
            
            # Update last detection time
            self.detected_persons[name] = now
            
            if name == "Unknown":
                status = "Unauthorized"
                details = self.handle_unknown_face(frame, top, right, bottom, left)
                
                # Send SMS alert for unauthorized person
                alert_msg = (f"SECURITY ALERT: Unauthorized person detected at {self.current_location} "
                           f"on {now.strftime('%Y-%m-%d %H:%M:%S')}")
                self.send_sms_alert(alert_msg)
            elif self.is_restricted_hours():
                status = "Unauthorized"
                details = "Entry during restricted hours"
                
                # Send SMS alert for restricted hours access
                alert_msg = (f"SECURITY ALERT: {name} accessed at {self.current_location} "
                           f"during restricted hours on {now.strftime('%Y-%m-%d %H:%M:%S')}")
                self.send_sms_alert(alert_msg)
            
            # Draw annotations
            color = (0, 255, 0) if status == "Authorized" else (0, 0, 255)
            cv2.rectangle(frame, (left, top), (right, bottom), color, 2)
            cv2.putText(frame, f"{name} ({status})", (left, top - 10), 
                       cv2.FONT_HERSHEY_SIMPLEX, 0.6, color, 2)
            
            # Log access
            self.log_access(
                timestamp=now,
                location=self.current_location,
                name=name,
                status=status,
                details=details
            )
        
        # Convert to RGB for display
        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        self.display_frame(rgb_frame)
        self.update_status()
        
        # Clean up old detections
        self.cleanup_detected_persons()

    def cleanup_detected_persons(self):
        """Remove persons who haven't been detected in a while"""
        now = datetime.now()
        to_remove = [name for name, time in self.detected_persons.items() 
                    if (now - time).total_seconds() > CONFIG["DETECTION_COOLDOWN"] * 2]
        
        for name in to_remove:
            del self.detected_persons[name]

    def handle_unknown_face(self, frame, top, right, bottom, left):
        """Process unknown face detection"""
        # Save image of unknown face
        face_img = frame[top:bottom, left:right]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        img_path = os.path.join(
            CONFIG["DATA_DIR"], 
            CONFIG["UNAUTHORIZED_DIR"], 
            f"unknown_{timestamp}.jpg"
        )
        cv2.imwrite(img_path, face_img)
        
        # Check if we should trigger alert
        if not self.should_suppress_alert():
            self.trigger_alert(f"Unauthorized person detected at {self.current_location}")
        
        return "Unknown person"

    def should_suppress_alert(self):
        """Check if alert should be suppressed due to cooldown"""
        if self.last_alert_time is None:
            return False
        return (datetime.now() - self.last_alert_time).total_seconds() < CONFIG["ALERT_COOLDOWN"]

    def trigger_alert(self, message):
        """Handle security alerts"""
        self.last_alert_time = datetime.now()
        QMessageBox.warning(self, "Security Alert", message)
        
        # Play alert sound on Windows
        if sys.platform == "win32":
            winsound.Beep(1000, 1000)  # 1kHz beep for 1 second

    def test_alert(self):
        """Test the alert system"""
        self.trigger_alert("This is a test of the alert system")

    def update_location(self, location):
        """Update current monitoring location"""
        self.current_location = location
        self.update_status()

    def display_frame(self, frame):
        """Display camera frame in UI"""
        h, w, ch = frame.shape
        bytes_per_line = ch * w
        q_img = QImage(frame.data, w, h, bytes_per_line, QImage.Format_RGB888)
        self.camera_display.setPixmap(QPixmap.fromImage(q_img))

    def update_status(self):
        """Update status bar"""
        self.status_bar.showMessage(
            f"Location: {self.current_location} | "
            f"Occupancy: {self.current_occupancy}/{CONFIG['MAX_OCCUPANCY']} | "
            f"Status: {'Restricted' if self.is_restricted_hours() else 'Normal'} | "
            f"Last Alert: {self.last_alert_time.strftime('%H:%M:%S') if self.last_alert_time else 'None'} | "
            f"SMS Alerts: {'ON' if self.sms_alerts_enabled else 'OFF'}"
        )

    def is_restricted_hours(self):
        """Check if current time is in restricted hours"""
        now = datetime.now().time()
        start, end = CONFIG["RESTRICTED_HOURS"]
        return start <= now <= end if start <= end else (now >= start or now <= end)

    def log_access(self, **kwargs):
        """Log access attempt"""
        # Add to table
        row = self.access_log_table.rowCount()
        self.access_log_table.insertRow(row)
        
        for i, (key, value) in enumerate(kwargs.items()):
            self.access_log_table.setItem(row, i, QTableWidgetItem(str(value)))
        
        # Save to CSV
        with open(os.path.join(CONFIG["DATA_DIR"], CONFIG["ACCESS_LOG"]), "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=kwargs.keys())
            if f.tell() == 0:
                writer.writeheader()
            writer.writerow(kwargs)

    def load_access_logs(self):
        """Load access logs from file"""
        try:
            with open(os.path.join(CONFIG["DATA_DIR"], CONFIG["ACCESS_LOG"]), "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    self.access_log_table.insertRow(self.access_log_table.rowCount())
                    for i, col in enumerate(reader.fieldnames):
                        self.access_log_table.setItem(
                            self.access_log_table.rowCount() - 1, 
                            i, 
                            QTableWidgetItem(row[col])
                        )
        except FileNotFoundError:
            pass

    def load_known_faces(self):
        """Load known faces from file"""
        try:
            with open(os.path.join(CONFIG["DATA_DIR"], CONFIG["KNOWN_FACES_FILE"]), "rb") as f:
                data = pickle.load(f)
                self.known_faces = data["encodings"]
                self.known_names = data["names"]
                # Update worker with loaded faces
                if hasattr(self, 'face_worker'):
                    self.face_worker.known_faces = self.known_faces
                    self.face_worker.known_names = self.known_names
        except (FileNotFoundError, EOFError):
            self.known_faces = []
            self.known_names = []

    def register_face(self):
        """Register a new authorized face"""
        name, ok = QInputDialog.getText(self, "Register Face", "Enter person's name:")
        if not ok or not name:
            return
        
        # Capture face image
        ret, frame = self.cap.read()
        if not ret:
            QMessageBox.warning(self, "Error", "Failed to capture image")
            return
        
        # Detect and encode face
        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        face_locations = face_recognition.face_locations(rgb_frame)
        
        if not face_locations:
            QMessageBox.warning(self, "Error", "No face detected in frame")
            return
        
        face_encoding = face_recognition.face_encodings(rgb_frame, face_locations)[0]
        
        # Add to known faces
        self.known_faces.append(face_encoding)
        self.known_names.append(name)
        
        # Update worker
        if hasattr(self, 'face_worker'):
            self.face_worker.known_faces = self.known_faces
            self.face_worker.known_names = self.known_names
        
        # Save to file
        self.save_known_faces()
        
        # Save face image
        img_path = os.path.join(
            CONFIG["DATA_DIR"], 
            CONFIG["UNAUTHORIZED_DIR"], 
            f"{name.replace(' ', '_')}.jpg"
        )
        cv2.imwrite(img_path, frame)
        
        QMessageBox.information(self, "Success", f"Successfully registered {name}")

    def save_known_faces(self):
        """Save known faces to file"""
        with open(os.path.join(CONFIG["DATA_DIR"], CONFIG["KNOWN_FACES_FILE"]), "wb") as f:
            pickle.dump({
                "encodings": self.known_faces,
                "names": self.known_names
            }, f)

    def view_registered_faces(self):
        """Display registered faces"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Registered Persons")
        dialog.setMinimumSize(400, 300)
        
        layout = QVBoxLayout()
        face_list = QListWidget()
        face_list.addItems(self.known_names)
        
        layout.addWidget(face_list)
        dialog.setLayout(layout)
        dialog.exec_()

    def setup_face_detection(self):
        """Initialize the face detection system"""
        self.face_worker = FaceDetector(self.known_faces, self.known_names)
        self.detection_thread = QThread()
        self.face_worker.moveToThread(self.detection_thread)
        
        # Connect signals
        self.face_worker.detection_complete.connect(self.handle_detection_results)
        self.face_worker.finished.connect(self.on_detection_finished)
        
        # Start thread
        self.detection_thread.start()

    def on_detection_finished(self):
        """Slot called when face detection completes"""
        pass

    def closeEvent(self, event):
        """Cleanup on exit"""
        # Stop camera
        if self.camera_active:
            self.stop_camera()
        
        # Stop detection thread
        if hasattr(self, 'detection_thread'):
            self.detection_thread.quit()
            self.detection_thread.wait()
        
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Set application-wide font
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    
    window = UnauthorizedEntrySystem()
    window.show()
    
    sys.exit(app.exec_())
