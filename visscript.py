import sys
import networkx as nx
import matplotlib.pyplot as plt
from PyQt5.QtWidgets import QApplication, QMainWindow, QSizePolicy
from PyQt5.QtCore import QTimer
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas

import numpy as np

class GraphWindow(QMainWindow):
    def __init__(self, graph, interval=100):
        super().__init__()

        self.graph = graph
        self.positions = None
        self.damping_factor = 0.9

        # Set up the canvas for plotting the graph
        self.figure = plt.figure()
        self.canvas = FigureCanvas(self.figure)
        self.canvas.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setCentralWidget(self.canvas)

        # Set up a timer to update the graph visualization
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_graph)
        self.timer.start(interval)

    def update_graph(self):
        # Clear the current plot
        self.figure.clear()

        # If positions haven't been initialized, create initial positions using spring layout
        if self.positions is None:
            self.positions = nx.spring_layout(self.graph, seed=42)

        # Create a new layout based on the current graph
        new_positions = nx.spring_layout(self.graph, pos=self.positions, iterations=5, seed=42)

        # Update positions with damping factor
        for node in self.positions:
            self.positions[node] = (
                self.positions[node] * self.damping_factor +
                new_positions[node] * (1 - self.damping_factor)
            )

        # Draw the updated graph
        nx.draw(self.graph, self.positions, with_labels=True, node_color="skyblue", node_size=1500, edge_color="gray", font_size=12, font_weight="bold", width=2, alpha=0.8)

        # Update the canvas with the new graph visualization
        self.canvas.draw()



#def main():
#    # Create a sample graph
#    graph = nx.DiGraph()
#    graph.add_edges_from([(1, 2), (1, 3), (3, 4)])
#
#    # Create the application and the main window
#    app = QApplication(sys.argv)
#    window = GraphWindow(graph)
#    window.show()
#
#    # Update the graph every 2 seconds (change this to your desired update interval)
#    def update_graph_data():
#        # Modify the graph data here as needed
#        pass
#
#    timer = QTimer()
#    timer.timeout.connect(update_graph_data)
#    timer.start(2000)
#
#    # Run the application
#    sys.exit(app.exec_())

def main():
    # Create the application and the main window
    app = QApplication(sys.argv)
    window = GraphWindow(None)
    window.show()

    # Run the application
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
